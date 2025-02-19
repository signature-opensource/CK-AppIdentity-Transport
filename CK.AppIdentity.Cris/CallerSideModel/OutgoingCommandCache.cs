using CK.Core;
using CK.Cris;
using CK.PerfectEvent;
using System.Collections.Concurrent;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris;

/// <summary>
/// Factory for outgoing <see cref="IEventRequest{T}"/> and <see cref="IOutgoingCommand{T}"/> requests.
/// <para>
/// This must be used by endpoint implementations.
/// </para>
/// </summary>
public class OutgoingCommandCache
{
    // Holds the created and not yet completed requests.
    readonly ConcurrentDictionary<ActivityMonitor.LogKey, OutgoingCommand> _cache;
    readonly IPocoFactory<ICrisResultError> _errorFactory;
    readonly PerfectEventSender<IOutgoingCommand, IEvent>? _onEventRelay;

    /// <summary>
    /// Initializes a new <see cref="OutgoingCommandCache"/>. This must be bound and used internally
    /// by an endpoint.
    /// </summary>
    /// <param name="errorFactory">Required error factory (used to create an error for a failed <see cref="CrisValidationResult"/>).</param>
    /// <param name="onEventRelay">Optional event sender to which events emitted by commands will be relayed.</param>
    public OutgoingCommandCache( IPocoFactory<ICrisResultError> errorFactory,
                                 PerfectEventSender<IOutgoingCommand,IEvent>? onEventRelay = null )
    {
        _cache = new ConcurrentDictionary<ActivityMonitor.LogKey, OutgoingCommand>();
        _errorFactory = errorFactory;
        _onEventRelay = onEventRelay;
    }

    /// <summary>
    /// Creates a new command request.
    /// </summary>
    /// <typeparam name="T">The type of the command.</typeparam>
    /// <param name="monitor">The <see cref="IActivityMonitor"/> or <see cref="IParallelLogger"/> to use to generate the <see cref="IOutgoingCommand.IssuerToken"/>.</param>
    /// <param name="c">The command payload.</param>
    /// <param name="extraData">Request data specific to the endpoint (Authentication token for instance).</param>
    /// <returns>A new command request.</returns>
    public IOutgoingCommand<T> CreateCommand<T>( IActivityDependentTokenFactory monitor, T c, object? extraData ) where T : class, IAbstractCommand
    {
        var token = monitor.CreateToken( null, dependentTopic: $"Handling '{c.CrisPocoModel.PocoName}' command." );
        return CreateCommand( c, token, extraData );
    }

    /// <summary>
    /// Creates a new command request.
    /// </summary>
    /// <typeparam name="T">The type of the command.</typeparam>
    /// <param name="c">The command payload.</param>
    /// <param name="issuerToken">The <see cref="IOutgoingCommand.IssuerToken"/>.</param>
    /// <param name="extraData">Request data specific to the endpoint (Authentication token for instance).</param>
    /// <returns>A new command request.</returns>
    public IOutgoingCommand<T> CreateCommand<T>( T c, ActivityMonitor.Token issuerToken, object? extraData ) where T : class, IAbstractCommand
    {
        var request = new OutgoingCommand<T>( this, c, issuerToken, extraData, _onEventRelay );
        Throw.CheckState( _cache.TryAdd( issuerToken.Key, request ) );
        return request;
    }

    /// <summary>
    /// Sets the validation result of a request. There is no "TrySetValidationResult": the validation result must be set once and only once.
    /// If this is an event or a command without result, this immediately completes the request.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="id">The <see cref="IOutgoingCommand.IssuerToken"/> key.</param>
    /// <param name="v">The validation result received from the callee.</param>
    public void SetValidationResult( IParallelLogger logger, ActivityMonitor.LogKey id, CrisValidationResult v )
    {
        if( _cache.TryGetValue( id, out var r ) )
        {
            if( r.SetValidationResult( logger, _errorFactory, v ) )
            {
                _cache.TryRemove( id, out _ );
            }
            else
            {
                OnValidationReceived( logger, r );
            }
        }
    }

    /// <summary>
    /// Collects event emitted by command handling.
    /// </summary>
    /// <param name="monitor">The logger.</param>
    /// <param name="id">The <see cref="IOutgoingCommand.IssuerToken"/> key.</param>
    /// <param name="e">The event received from the callee.</param>
    public Task CollectCommandEventAsync( IActivityMonitor monitor, ActivityMonitor.LogKey id, IEvent e )
    {
        if( _cache.TryGetValue( id, out var r ) )
        {
            return r.AddCommandEventAsync( monitor, e );
        }
        else
        {
            monitor.Error( $"Received event for an unknown request '{id}'. This is ignored." );
        }
        return Task.CompletedTask;
    }

    /// <summary>
    /// Sets the final result. There is no "TrySetFinalResult": the result must be set once and only once.
    /// </summary>
    /// <param name="result">The request result. Null for event or command without result.</param>
    public void SetResult( IParallelLogger logger, ActivityMonitor.LogKey id, object? result )
    {
        if( _cache.TryRemove( id, out var r ) )
        {
            r.SetResult( logger, result );
        }
    }

    internal protected virtual void OnSetSentDate( IParallelLogger logger, OutgoingCommand outgoingRequest )
    {
    }

    internal protected virtual void OnValidationReceived( IParallelLogger logger, OutgoingCommand r )
    {
    }

    internal protected virtual void OnRequestCompleted( IParallelLogger logger, OutgoingCommand outgoingRequest )
    {
    }

}
