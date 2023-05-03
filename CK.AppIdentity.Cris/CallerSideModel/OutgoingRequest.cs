using CK.Core;
using CK.Cris;
using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris
{
    public class OutgoingRequest : IOutgoingRequest
    {
        readonly ICrisPoco _payload;
        readonly ActivityMonitor.Token _issuerToken;
        readonly TaskCompletionSource<DateTime> _sentDate;
        readonly TaskCompletionSource<CrisValidationResult> _validation;
        readonly TaskCompletionSource<object?> _completion;
        readonly object? _extraData;
        private protected readonly OutgoingRequestCache _cache;

        internal OutgoingRequest( OutgoingRequestCache cache,
                                  ICrisPoco payload,
                                  ActivityMonitor.Token issuerToken,
                                  object? extraData )
        {
            _issuerToken = issuerToken;
            _extraData = extraData;
            _cache = cache;
            _payload = payload;
            _sentDate = new TaskCompletionSource<DateTime>();
            _validation = new TaskCompletionSource<CrisValidationResult>();
            _completion = new TaskCompletionSource<object?>();
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
                SetResult( logger, errorFactory.Create( e => e.Errors.AddRange( v.Errors ) ) );
                return true;
            }
            if( _payload.CrisPocoModel.IsEvent )
            {
                SetResult( logger, null );
                return true;
            }
            return false;
        }

        internal virtual Task AddCommandEventAsync( IActivityMonitor monitor, IEvent e )
        {
            monitor.Error( $"Received event for a request '{IssuerToken.Key}' that is an event. This is ignored." );
            return Task.CompletedTask;
        }

        internal virtual void SetResult( IParallelLogger logger, object? result )
        {
            _completion.SetResult( result );
            _cache.OnRequestCompleted( logger, this );
        }

    }

}
