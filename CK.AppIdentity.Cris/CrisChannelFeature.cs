using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Cris;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris;

/// <summary>
/// Sends Cris commands to the <see cref="ChannelFeature.Party"/> and executes the commands it sends.
/// <para>
/// A command received from the remote is executed with the default (anonymous) ambient services: the
/// only identity that is established is the one of the remote party itself, that is available as a
/// scoped <see cref="IRemoteParty"/> service. Nothing in the message can claim a user identity.
/// </para>
/// <para>
/// A remote may only send the commands this party accepts from it (see <see cref="IsAcceptedFromRemote(ICrisPocoModel)"/>):
/// on each connection, each side advertises them to the other (see <see cref="AcceptedCommands"/>). The other ones are
/// refused before any validation.
/// </para>
/// </summary>
public sealed partial class CrisChannelFeature : ChannelFeature
{
    readonly PocoDirectory _pocoDirectory;
    readonly IPocoFactory<ICrisResultError> _errorFactory;
    readonly IPocoFactory<ICrisCallResult> _callResultFactory;
    readonly IncomingCommandExecutor _executor;
    readonly CrisDirectory _crisDirectory;
    readonly ICrisChannelReceptionHandler? _receptionHandler;
    // The call contexts of the commands not yet sent.
    readonly ConcurrentDictionary<ActivityMonitor.LogKey, ICrisCallContext> _callContexts;
    // The command names the remote accepts from us: null until its first advertisement.
    volatile IReadOnlySet<string>? _acceptedCommands;
    readonly TaskCompletionSource _firstAccepted;
    // The final caller-only events received for a command not yet executed.
    readonly ConcurrentDictionary<ActivityMonitor.LogKey, List<IEvent>> _finalEvents;
    // The commands sent and not yet executed (this includes the ones still in _toSend).
    // A command is completed exactly once: by the one that removes it from here.
    readonly ConcurrentDictionary<ActivityMonitor.LogKey, ExecutingCommand> _executing;
    // Commands to send in order. The send loop waits for the first handler to exist.
    readonly Channel<ExecutingCommand> _toSend;
    // Resolved with the first handler (or null on teardown).
    readonly TaskCompletionSource<Protocol?> _firstHandler;
    // The latest handler. Once a handler exists, its messages are queued by the transport controller
    // that outlives the connections: a message enqueued while disconnected is sent on reconnection.
    volatile Protocol? _handler;

    internal CrisChannelFeature( TransportFeature transportFeature,
                                 PocoDirectory pocoDirectory,
                                 IPocoFactory<ICrisResultError> errorFactory,
                                 IPocoFactory<ICrisCallResult> callResultFactory,
                                 CrisExecutionHost executionHost,
                                 IDIContainer<AppIdentityDIContainerDefinition.Data> endpoint,
                                 CrisDirectory crisDirectory,
                                 ICrisChannelReceptionHandler? receptionHandler )
        : base( transportFeature )
    {
        _pocoDirectory = pocoDirectory;
        _crisDirectory = crisDirectory;
        _receptionHandler = receptionHandler;
        _callContexts = new ConcurrentDictionary<ActivityMonitor.LogKey, ICrisCallContext>();
        _firstAccepted = new TaskCompletionSource( TaskCreationOptions.RunContinuationsAsynchronously );
        _finalEvents = new ConcurrentDictionary<ActivityMonitor.LogKey, List<IEvent>>();
        _errorFactory = errorFactory;
        _callResultFactory = callResultFactory;
        _executor = new IncomingCommandExecutor( this, executionHost, endpoint );
        _executing = new ConcurrentDictionary<ActivityMonitor.LogKey, ExecutingCommand>();
        _toSend = Channel.CreateUnbounded<ExecutingCommand>( new UnboundedChannelOptions { SingleReader = true } );
        _firstHandler = new TaskCompletionSource<Protocol?>( TaskCreationOptions.RunContinuationsAsynchronously );
        _ = Task.Run( SendLoopAsync );
    }

    protected override PeerProtocolHandler CreateHandler( IActivityMonitor monitor, ref PeerProtocolHandler.CreateParameters c )
    {
        Throw.DebugAssert( c.Protocol.Version == 0 );
        return new Protocol( this, ref c );
    }

    protected override void OnCurrentHandlerChanged( IActivityMonitor monitor, PeerProtocolHandler? previous, PeerProtocolHandler? current )
    {
        if( current != null )
        {
            var h = (Protocol)current;
            _handler = h;
            _firstHandler.TrySetResult( h );
            // On each connection, we tell the remote what it may send us.
            h.SendAccepted( monitor, _crisDirectory.CrisPocoModels.Where( IsAcceptedFromRemote ).Select( m => m.PocoName ).ToList() );
        }
    }

    /// <summary>
    /// Gets whether the remote <see cref="ChannelFeature.Party"/> is inside the System of its owner (our local party):
    /// it shares its <see cref="IParty.DomainName"/> and <see cref="IParty.EnvironmentName"/>.
    /// </summary>
    public bool IsRemoteInsideSystem => Party.DomainName == Party.Owner.DomainName
                                        && Party.EnvironmentName == Party.Owner.EnvironmentName;

    /// <summary>
    /// Gets whether a command can be received from the remote: it is a command handled here, not <see cref="CrisExposure.Private"/>
    /// and, when it is <see cref="CrisExposure.Internal"/>, the remote is inside the System (see <see cref="IsRemoteInsideSystem"/>).
    /// Endpoint-only commands are accepted (they are sent explicitly, never dispatched).
    /// </summary>
    /// <param name="model">The command model.</param>
    /// <returns>True if the remote may send it.</returns>
    public bool IsAcceptedFromRemote( ICrisPocoModel model )
    {
        return model.Kind is CrisPocoKind.Command or CrisPocoKind.CommandWithResult
               && model.IsHandled
               && model.Exposure switch
               {
                   CrisExposure.Public => true,
                   CrisExposure.Internal => IsRemoteInsideSystem,
                   _ => false
               };
    }

    /// <summary>
    /// Gets the names of the commands that the remote accepts from us (its advertisement, received on each connection),
    /// or null until the first one is received.
    /// </summary>
    public IReadOnlySet<string>? AcceptedCommands => _acceptedCommands;

    /// <summary>
    /// Waits for the first advertisement of the remote (see <see cref="AcceptedCommands"/>).
    /// </summary>
    /// <param name="timeout">The maximal time to wait.</param>
    /// <returns>True if the remote has advertised its accepted commands, false on timeout.</returns>
    public async Task<bool> WaitForAcceptedCommandsAsync( TimeSpan timeout )
    {
        if( _acceptedCommands != null ) return true;
        try
        {
            await _firstAccepted.Task.WaitAsync( timeout ).ConfigureAwait( false );
            return _acceptedCommands != null;
        }
        catch( TimeoutException )
        {
            return false;
        }
    }

    internal void OnAccepted( IActivityMonitor monitor, HashSet<string> names )
    {
        _acceptedCommands = names;
        _firstAccepted.TrySetResult();
        monitor.Info( $"'{Party.FullName}' accepts {names.Count} commands from '{Party.Owner.FullName}'." );
        // Singleton commands: one eventual handler in the tenant (the local party), a local handler always wins.
        foreach( var other in Party.Owner.Remotes )
        {
            if( other == Party || other.GetFeature<CrisChannelFeature>()?.AcceptedCommands is not { } o ) continue;
            foreach( var name in names )
            {
                if( o.Contains( name )
                    && _crisDirectory.CrisPocoModels.FirstOrDefault( m => m.PocoName == name ) is { IsHandled: false } m
                    && !typeof( ICommandTargetParty ).IsAssignableFrom( m.CommandType ) )
                {
                    monitor.Error( $"Deployment error: command '{name}' is handled by '{Party.FullName}' and '{other.FullName}' for '{Party.Owner.FullName}'. It cannot be dispatched." );
                }
            }
        }
    }

    internal void OnFinalEvent( IActivityMonitor monitor, ActivityMonitor.LogKey key, IEvent e )
    {
        if( !_executing.ContainsKey( key ) )
        {
            monitor.Warn( $"Received final event '{e.CrisPocoModel.PocoName}' from '{Party.FullName}' for unknown command '{key}'. Ignored." );
            return;
        }
        var events = _finalEvents.GetOrAdd( key, _ => new List<IEvent>() );
        lock( events ) events.Add( e );
    }

    /// <summary>
    /// Gets the poco directory (to create the commands to send).
    /// </summary>
    public PocoDirectory PocoDirectory => _pocoDirectory;

    /// <summary>
    /// Sends a command to the remote party.
    /// <para>
    /// This never throws: the returned <see cref="IExecutingCommand{T}.ExecutedCommand"/> eventually carries
    /// the remote result or a <see cref="ICrisResultError"/> if the command cannot be sent or its result cannot be read.
    /// The command is sent as soon as a connection to the remote is established.
    /// </para>
    /// <para>
    /// Only the caller-only events cross the channel (they travel with the response): the immediate ones appear in
    /// <see cref="IExecutingCommand.ImmediateEvents"/>, the final ones in <see cref="IExecutedCommand.Events"/>. The routed
    /// events are dispatched in the remote party, where the command executed.
    /// </para>
    /// </summary>
    /// <typeparam name="T">The command type.</typeparam>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The command to send.</param>
    /// <param name="issuerToken">Optional issuer token. When null a new token is obtained from the <paramref name="monitor"/>.</param>
    /// <param name="callContext">Optional call context sent with the command (see <see cref="ICrisCallContext"/>).</param>
    /// <returns>The executing command.</returns>
    public IExecutingCommand<T> SendCommand<T>( IActivityMonitor monitor, T command, ActivityMonitor.Token? issuerToken = null, ICrisCallContext? callContext = null )
        where T : class, IAbstractCommand
    {
        Throw.CheckNotNullArgument( monitor );
        Throw.CheckNotNullArgument( command );
        issuerToken ??= monitor.CreateToken( $"Sending '{command.CrisPocoModel.PocoName}' command to '{Party.FullName}'." );
        var executing = new ExecutingCommand<T>( command, issuerToken );
        if( !_executing.TryAdd( issuerToken.Key, executing ) )
        {
            Throw.ArgumentException( nameof( issuerToken ), $"Issuer token '{issuerToken.Key}' is already used by a command being sent to '{Party.FullName}'." );
        }
        if( callContext != null ) _callContexts[issuerToken.Key] = callContext;
        if( !_toSend.Writer.TryWrite( executing ) )
        {
            monitor.Warn( $"Channel to '{Party.FullName}' is closed. Command '{command.CrisPocoModel.PocoName}' cannot be sent." );
            SetError( issuerToken.Key, $"Remote '{Party.FullName}' is no more available." );
        }
        else if( _handler == null )
        {
            monitor.Info( $"No connection to '{Party.FullName}' yet. Command '{command.CrisPocoModel.PocoName}' will be sent once connected." );
        }
        return executing;
    }

    async Task SendLoopAsync()
    {
        var h = await _firstHandler.Task.ConfigureAwait( false );
        await foreach( var c in _toSend.Reader.ReadAllAsync().ConfigureAwait( false ) )
        {
            if( h == null )
            {
                SetError( c.IssuerToken.Key, $"Remote '{Party.FullName}' is no more available." );
                continue;
            }
            // A reconnection may have created a new handler.
            h = _handler ?? h;
            IOutgoingMessage message;
            try
            {
                _callContexts.TryRemove( c.IssuerToken.Key, out var callContext );
                message = h.CreateCommandMessage( c, callContext );
            }
            catch( System.Exception ex )
            {
                ActivityMonitor.StaticLogger.Error( $"Unable to serialize command '{c.Command.CrisPocoModel.PocoName}' for '{Party.FullName}'.", ex );
                SetError( c.IssuerToken.Key, "Unable to serialize the command." );
                continue;
            }
            if( !await h.TryEnqueueAsync( message ).ConfigureAwait( false ) )
            {
                message.Dispose();
                SetError( c.IssuerToken.Key, $"Remote '{Party.FullName}' is no more available." );
            }
        }
    }

    internal Task OnImmediateEventAsync( IActivityMonitor monitor, ActivityMonitor.LogKey key, IEvent e )
    {
        if( _executing.TryGetValue( key, out var c ) )
        {
            return c.DarkSide.AddImmediateEventAsync( monitor, e );
        }
        monitor.Warn( $"Received immediate event '{e.CrisPocoModel.PocoName}' from '{Party.FullName}' for unknown command '{key}'. Ignored." );
        return Task.CompletedTask;
    }

    internal void OnExecuted( IActivityMonitor monitor, ActivityMonitor.LogKey key, ICrisCallResult? result )
    {
        bool known = result != null
                        ? Complete( key, result.Result, result.ValidationMessages?.ToImmutableArray() ?? ImmutableArray<UserMessage>.Empty )
                        : SetError( key, "Unable to read the command result." );
        if( !known )
        {
            monitor.Warn( $"Received a result from '{Party.FullName}' for unknown command '{key}'. Ignored." );
        }
    }

    bool SetError( ActivityMonitor.LogKey key, string message )
    {
        var error = _errorFactory.Create( e => e.Errors.Add( new UserMessage( UserMessageLevel.Error,
                                                                              MCString.CreateNonTranslatable( NormalizedCultureInfo.CodeDefault, message ) ) ) );
        return Complete( key, error, ImmutableArray<UserMessage>.Empty );
    }

    bool Complete( ActivityMonitor.LogKey key, object? result, ImmutableArray<UserMessage> validationMessages )
    {
        if( _executing.TryRemove( key, out var c ) )
        {
            _callContexts.TryRemove( key, out _ );
            var command = c.Command;
            var events = _finalEvents.TryRemove( key, out var finals ) ? finals.ToImmutableArray() : ImmutableArray<IEvent>.Empty;
            c.DarkSide.SetResult( command.CrisPocoModel.CreateExecutedCommand( command, result, validationMessages, events, c ) );
            return true;
        }
        return false;
    }

    protected override void Teardown( FeatureLifetimeContext context )
    {
        _toSend.Writer.TryComplete();
        _firstHandler.TrySetResult( null );
        _firstAccepted.TrySetResult();
        foreach( var key in _executing.Keys )
        {
            SetError( key, $"Remote '{Party.FullName}' is no more available." );
        }
    }
}
