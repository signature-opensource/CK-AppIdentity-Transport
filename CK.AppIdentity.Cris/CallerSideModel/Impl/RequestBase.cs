using CK.Core;
using CK.Cris;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris
{
    class RequestBase : IOutgoingRequest
    {
        readonly ICrisPoco _payload;
        readonly ActivityMonitor.DependentToken _depToken;
        readonly TaskCompletionSource<DateTime> _sentDate;
        readonly TaskCompletionSource<object?> _completion;

        public RequestBase( ICrisPoco payload, ActivityMonitor.DependentToken depToken )
        {
            _depToken = depToken;
            _payload = payload;
            _sentDate = new TaskCompletionSource<DateTime>();
            _completion = new TaskCompletionSource<object?>();
        }

        public ICrisPoco Payload => _payload;

        public ActivityMonitor.DependentToken IssuerToken => _depToken;

        public DateTime CreationDate => _depToken.CreationDate.TimeUtc;

        public Task<DateTime> SentDate => _sentDate.Task;

        internal void SetSentDate( DateTime time ) => _sentDate.SetResult( time );

        public Task<object?> RequestCompletion => _completion.Task;

        internal void SetResult( object? result ) => _completion.SetResult( result );
    }

}
