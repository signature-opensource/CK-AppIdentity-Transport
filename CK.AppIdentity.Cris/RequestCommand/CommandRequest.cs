using CK.Core;
using CK.Cris;
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using static CK.Core.CheckedWriteStream;

namespace CK.AppIdentity.Cris
{
    class CommandRequest : ICommandRequest
    {
        readonly ICommand _command;
        readonly ActivityMonitor.DependentToken _depToken;
        readonly string? _authToken;
        readonly Collector<ICommandRequest, ICrisEvent> _events;
        readonly TaskCompletionSource<DateTime> _sentDate;
        readonly TaskCompletionSource<CommandValidationResult> _validation;
        readonly TaskCompletionSource<ICrisResultError?> _completion;

        public CommandRequest( ICommand command, ActivityMonitor.DependentToken depToken, string? authToken )
        {
            _depToken = depToken;
            _authToken = authToken;
            _command = command;
            _events = new Collector<ICommandRequest, ICrisEvent>();
            _sentDate = new TaskCompletionSource<DateTime>();
            _validation = new TaskCompletionSource<CommandValidationResult>();
            _completion = new TaskCompletionSource<ICrisResultError?>();
        }

        public ICommand Command => _command;

        public ActivityMonitor.DependentToken UniqueId => _depToken;

        public DateTime CreationDate => _depToken.CreationDate.TimeUtc;

        public bool HasAuthenticationToken => _authToken != null;

        public Task<DateTime> SentDate => _sentDate.Task;

        public Task<CommandValidationResult> ValidationResult => _validation.Task;

        public Task<ICrisResultError?> Completion => _completion.Task;

        public ICollector<ICommandRequest, ICrisEvent> Events => _events;

        internal void SetSentDate( DateTime time ) => _sentDate.SetResult( time );

        internal void SetValidationResult( IPocoFactory<ICrisResultError> errorFactory, CommandValidationResult v, bool successfulComplete )
        {
            _validation.SetResult( v );
            if( !v.Success )
            {
                _completion.SetResult( errorFactory.Create( e => e.Errors.AddRange( v.Errors ) ) );
            }
            else if( successfulComplete )
            {
                _completion.SetResult( null );
            }
        }

        protected void SetSuccessfulComplete()
        {
            Debug.Assert( _validation.Task.IsCompletedSuccessfully && _validation.Task.Result.Success );
            _completion.SetResult( null );
        }
    }

    class CommandRequest<T> : CommandRequest, ICommandRequest<T> where T : class, ICommand
    {
        public CommandRequest( ICommand command, ActivityMonitor.DependentToken depToken, string? authToken )
            : base( command, depToken, authToken )
        {
        }

        public new T Command => Unsafe.As<T>( base.Command );

        internal void SetResult() => SetSuccessfulComplete();
    }

    sealed class CommandRequest<T,TResult> : CommandRequest<T>, ICommandRequest<T,TResult> where T : class, ICommand<TResult>
    {
        readonly TaskCompletionSource<TResult> _result;

        public CommandRequest( ICommand command, ActivityMonitor.DependentToken depToken, string? authToken )
            : base( command, depToken, authToken )
        {
            _result = new TaskCompletionSource<TResult>();
        }

        public new T Command => Unsafe.As<T>( base.Command );

        public Task<TResult> Result => _result.Task;

        internal void SetResult( TResult result )
        {
            SetSuccessfulComplete();
            _result.SetResult( result );
        }
    }

}
