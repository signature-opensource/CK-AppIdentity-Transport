using CK.Core;
using CK.Cris;
using CK.PerfectEvent;
using System;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris;

sealed class OutgoingCommand<T> : OutgoingCommand, IOutgoingCommand<T> where T : class, IAbstractCommand
{
    public OutgoingCommand( OutgoingCommandCache cache,
                            T command,
                            ActivityMonitor.Token issuerToken,
                            object? extraData,
                            PerfectEventSender<IOutgoingCommand, IEvent>? onEventRelay )
        : base( cache, command, issuerToken, extraData, onEventRelay )
    {
    }

    public T Command => Unsafe.As<T>( Payload );

    sealed class ResultAdapter<TResult> : IOutgoingCommand<T>.WithResult<TResult>
    {
        readonly OutgoingCommand<T> _command;
        readonly TaskCompletionSource<TResult> _result;

        public ResultAdapter( OutgoingCommand<T> command )
        {
            _command = command;
            _result = new TaskCompletionSource<TResult>();
            _ = _command.RequestCompletion.ContinueWith( OnRequestCompletion!, _result, default, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default );
        }

        static void OnRequestCompletion( Task<object?> c, object target )
        {
            var _result = (TaskCompletionSource<TResult>)target;
            // Don't take any risk: even if there should not be Faulted or Canceled state
            // on the RequestCompletion, transfers it if it happens.
            if( c.Exception != null ) _result.SetException( c.Exception );
            else if( c.IsCanceled ) _result.SetCanceled();
            else
            {
                Throw.DebugAssert( c.IsCompletedSuccessfully );
                // If the completion is a ICrisResultError, resolves the result task with an exception.
#pragma warning disable VSTHRD002 // c.IsCompletedSuccessfully is true.
                var r = c.Result;
#pragma warning restore VSTHRD002 // Avoid problematic synchronous waits
                if( r is ICrisResultError error )
                {
                    _result.SetException( error.CreateException() );
                }
                else
                {
                    // No error, the completion is null or an instance of some type (the most precise type among
                    // the different ICommand<TResult> TResult types.
                    // Fast path is that the result type is fine.
                    if( r is TResult typedResult )
                    {
                        _result.SetResult( typedResult );                            
                    }
                    else
                    {
                        // What's this type?
                        // If TResult allows it, it's fine (the trick is to use the default(T) here).
                        if( r == null )
                        {
                            if( default( TResult ) == null )
                            {
                                _result.SetResult( default( TResult )! );
                            }
                            else
                            {
                                var ex = new CKException( $"Request result is null. This is not compatible with '{typeof(TResult).ToCSharpName()}'." );
                                _result.SetException( ex );
                            }
                        }
                        else
                        {
                            var ex = new CKException( $"Request result is a '{r.GetType().ToCSharpName()}'. This is not compatible with '{typeof( TResult ).ToCSharpName()}'." );
                            _result.SetException( ex );
                        }
                    }
                }
            }
        }

        public Task<TResult> Result => _result.Task;

        public T Command => _command.Command;

        public Task<CrisValidationResult> ValidationResult => _command.ValidationResult;

        public ICollector<IOutgoingCommand, IEvent> Events => _command.Events;

        public IAbstractCommand Payload => _command.Payload;

        public ActivityMonitor.Token IssuerToken => _command.IssuerToken;

        public DateTime CreationDate => _command.CreationDate;

        public Task<DateTime> SentDate => _command.SentDate;

        public Task<object?> RequestCompletion => _command.RequestCompletion;
    }

    public IOutgoingCommand<T>.WithResult<TResult> WithResult<TResult>()
    {
        // Building a strongly typed result: we check that the actual result type (that is
        // the most precise type among the different ICommand<TResult> TResult types) is
        // compatible with the requested TResult.
        var requestedType = typeof( TResult );
        if( !requestedType.IsAssignableFrom( Payload.CrisPocoModel.ResultType ) )
        {
            if( Payload.CrisPocoModel.ResultType == typeof( void ) )
            {
                Throw.ArgumentException( $"Command '{Payload.CrisPocoModel.PocoName}' is a ICommand (without any result)." );
            }
            Throw.ArgumentException( $"Command '{Payload.CrisPocoModel.PocoName}' is a 'ICommand<{Payload.CrisPocoModel.ResultType.ToCSharpName()}>'." +
                                     $" This type of result is not compatible with '{requestedType.ToCSharpName()}'." );
        }
        return new ResultAdapter<TResult>( this );
    }

}
