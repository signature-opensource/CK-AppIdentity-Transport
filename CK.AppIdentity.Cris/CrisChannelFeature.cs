using CK.AppIdentity.TransportLayer;
using CK.Core;
using CK.Cris;
using System.Collections.Concurrent;
using System.Collections.Immutable;
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
/// </summary>
public sealed partial class CrisChannelFeature : ChannelFeature
{
    readonly PocoDirectory _pocoDirectory;
    readonly IPocoFactory<ICrisResultError> _errorFactory;
    readonly IPocoFactory<ICrisCallResult> _callResultFactory;
    readonly IncomingCommandExecutor _executor;
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
                                 IDIContainer<AppIdentityDIContainerDefinition.Data> endpoint )
        : base( transportFeature )
    {
        _pocoDirectory = pocoDirectory;
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
            _handler = (Protocol)current;
            _firstHandler.TrySetResult( _handler );
        }
    }

    /// <summary>
    /// Sends a command to the remote party.
    /// <para>
    /// This never throws: the returned <see cref="IExecutingCommand{T}.ExecutedCommand"/> eventually carries
    /// the remote result or a <see cref="ICrisResultError"/> if the command cannot be sent or its result cannot be read.
    /// The command is sent as soon as a connection to the remote is established.
    /// </para>
    /// <para>
    /// The <see cref="IExecutedCommand.Events"/> are always empty: the non immediate events are routed in the remote
    /// party. The immediate events emitted by the remote execution appear in <see cref="IExecutingCommand.ImmediateEvents"/>.
    /// </para>
    /// </summary>
    /// <typeparam name="T">The command type.</typeparam>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The command to send.</param>
    /// <param name="issuerToken">Optional issuer token. When null a new token is obtained from the <paramref name="monitor"/>.</param>
    /// <returns>The executing command.</returns>
    public IExecutingCommand<T> SendCommand<T>( IActivityMonitor monitor, T command, ActivityMonitor.Token? issuerToken = null )
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
                message = h.CreateCommandMessage( c );
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
            var command = c.Command;
            c.DarkSide.SetResult( command.CrisPocoModel.CreateExecutedCommand( command, result, validationMessages, ImmutableArray<IEvent>.Empty, c ) );
            return true;
        }
        return false;
    }

    protected override void Teardown( FeatureLifetimeContext context )
    {
        _toSend.Writer.TryComplete();
        _firstHandler.TrySetResult( null );
        foreach( var key in _executing.Keys )
        {
            SetError( key, $"Remote '{Party.FullName}' is no more available." );
        }
    }
}
