using CK.Core;
using CK.Cris;
using CK.PerfectEvent;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris;

public class OutgoingCommand : IOutgoingCommand
{
    readonly IAbstractCommand _payload;
    readonly ActivityMonitor.Token _issuerToken;
    readonly TaskCompletionSource<DateTime> _sentDate;
    readonly TaskCompletionSource<CrisValidationResult> _validation;
    readonly TaskCompletionSource<object?> _completion;
    readonly object? _extraData;
    readonly Collector<IOutgoingCommand, IEvent> _events;
    private protected readonly OutgoingCommandCache _cache;

    internal OutgoingCommand( OutgoingCommandCache cache,
                              IAbstractCommand payload,
                              ActivityMonitor.Token issuerToken,
                              object? extraData,
                              PerfectEventSender<IOutgoingCommand, IEvent>? onEventRelay )
    {
        _issuerToken = issuerToken;
        _extraData = extraData;
        _cache = cache;
        _payload = payload;
        _sentDate = new TaskCompletionSource<DateTime>();
        _validation = new TaskCompletionSource<CrisValidationResult>();
        _completion = new TaskCompletionSource<object?>();
        _events = new Collector<IOutgoingCommand, IEvent>( onEventRelay );
    }

    /// <inheritdoc />
    public IAbstractCommand Payload => _payload;

    /// <inheritdoc />
    public ActivityMonitor.Token IssuerToken => _issuerToken;

    /// <inheritdoc />
    public DateTime CreationDate => _issuerToken.CreationDate.TimeUtc;

    /// <inheritdoc />
    public Task<DateTime> SentDate => _sentDate.Task;

    public Task<CrisValidationResult> ValidationResult => _validation.Task;

    /// <inheritdoc />
    public Task<object?> RequestCompletion => _completion.Task;

    /// <inheritdoc />
    public ICollector<IOutgoingCommand, IEvent> Events => _events;

    /// <summary>
    /// Gets the extra data specific to the endpoint protocol.
    /// </summary>
    public object? ExtraData => _extraData;

    /// <summary>
    /// Sets the sent date. There is no "TrySetSentDate": the sent date must be set once and only once.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="time">The sent time of this request.</param>
    public void SetSentDate( IParallelLogger logger, DateTime time )
    {
        _sentDate.SetResult( time );
        _cache.OnSetSentDate( logger, this );
    }

    internal bool SetValidationResult( IParallelLogger logger, IPocoFactory<ICrisResultError> errorFactory, CrisValidationResult v )
    {
        _validation.SetResult( v );
        if( !v.Success )
        {
            SetResult( logger, errorFactory.Create( e => e.Errors.AddRange( v.ValidationMessages ) ) );
            return true;
        }
        // TODO: This has nothing to do here (just compiling for the moment).
        if( _payload.CrisPocoModel.Kind == CrisPocoKind.CallerOnlyEvent
            || _payload.CrisPocoModel.Kind == CrisPocoKind.RoutedEvent
            || _payload.CrisPocoModel.Kind == CrisPocoKind.RoutedImmediateEvent )
        {
            SetResult( logger, null );
            return true;
        }
        return false;
    }

    internal Task AddCommandEventAsync( IActivityMonitor monitor, IEvent e )
    {
        return _events.AddAsync( monitor, this, e );
    }

    internal void SetResult( IParallelLogger logger, object? result )
    {
        _completion.SetResult( result );
        _cache.OnRequestCompleted( logger, this );
        _events.Close();
    }

}
