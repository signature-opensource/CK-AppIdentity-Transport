using CK.Core;
using CK.Cris;
using CK.PerfectEvent;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris;

public class OutgoingCrisPoco : IOutgoingCrisPoco
{
    readonly ICrisPoco _payload;
    readonly ActivityMonitor.Token _issuerToken;
    readonly TaskCompletionSource<DateTime> _sentDate;
    readonly TaskCompletionSource<CrisValidationResult> _validation;
    readonly TaskCompletionSource<object?> _completion;
    readonly object? _extraData;
    readonly Collector<IOutgoingCrisPoco, IEvent> _events;
    private protected readonly OutgoingCache _cache;

    internal OutgoingCrisPoco( OutgoingCache cache,
                               ICrisPoco payload,
                               ActivityMonitor.Token issuerToken,
                               object? extraData,
                               PerfectEventSender<IOutgoingCrisPoco, IEvent>? onEventRelay )
    {
        _issuerToken = issuerToken;
        _extraData = extraData;
        _cache = cache;
        _payload = payload;
        _sentDate = new TaskCompletionSource<DateTime>();
        _validation = new TaskCompletionSource<CrisValidationResult>();
        _completion = new TaskCompletionSource<object?>();
        _events = new Collector<IOutgoingCrisPoco, IEvent>( onEventRelay );
    }

    /// <inheritdoc />
    public ICrisPoco Payload => _payload;

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
    public ICollector<IOutgoingCrisPoco, IEvent> Events => _events;

    /// <summary>
    /// Gets the extra data specific to the endpoint protocol.
    /// </summary>
    public object? ExtraData => _extraData;

    /// <summary>
    /// Sets the sent date. There is no "TrySetSentDate": the sent date must be set once and only once.
    /// </summary>
    /// <param name="time">The sent time of this request.</param>
    internal void SetSentDate( DateTime time ) => _sentDate.SetResult( time );

    internal bool SetValidationResult( IParallelLogger logger, IPocoFactory<ICrisResultError> errorFactory, CrisValidationResult v )
    {
        _validation.SetResult( v );
        if( !v.Success )
        {
            SetResult( logger, errorFactory.Create( e =>
            {
                e.IsValidationError = true;
                e.Errors.AddRange( v.ValidationMessages );
                e.LogKey = v.LogKey;
            } ) );
            return false;
        }
        // TODO: This has nothing to do here (just compiling for the moment).
        if( _payload.CrisPocoModel.Kind == CrisPocoKind.CallerOnlyEvent
            || _payload.CrisPocoModel.Kind == CrisPocoKind.RoutedEvent
            || _payload.CrisPocoModel.Kind == CrisPocoKind.RoutedImmediateEvent )
        {
            SetResult( logger, null );
            return false;
        }
        return true;
    }

    internal Task AddCommandEventAsync( IActivityMonitor monitor, IEvent e )
    {
        return _events.AddAsync( monitor, this, e );
    }

    internal void SetResult( IParallelLogger logger, object? result )
    {
        _completion.SetResult( result );
        _events.Close();
    }

}
