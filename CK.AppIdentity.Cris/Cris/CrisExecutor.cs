using CK.Core;
using CK.PerfectEvent;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace CK.Cris
{
    /// <summary>
    /// Non generic base class for <see cref="CrisExecutor{T}"/> that
    /// implements <see cref="ICrisExecutor"/> interface.
    /// </summary>
    [CKTypeSuperDefiner]
    [Setup.AlsoRegisterType( typeof( ICrisExecutorPayload ) )]
    public abstract partial class CrisExecutor : ICrisExecutor
    {
        readonly PerfectEventSender<ICrisExecutor> _parallelRunnerCountChanged;
        // We use null as the close signal for runners.
        // The _channel is used as the lock to manage runners.
        readonly Channel<object?> _channel;
        Runner? _last;
        int _runnerCount;
        int _plannedRunnerCount;
        // Ever increasing number.
        int _runnerNumber;

        /// <summary>
        /// The executor returns this result wrapper for 2 reasons:
        /// <list type="bullet">
        /// <item>
        /// This enables serialization to always consider any Poco serialization implementation
        /// and guaranties that only Poco compliant types are returned to the caller.
        /// </item>
        /// <item>
        /// This acts as a union type: the result is a <see cref="ICrisResultError"/>, or any other type
        /// or null. A <see cref="ICommand{TResult}"/> where TResult is a ICrisResultError can return
        /// an error (or null), and if TResult is <c>object?</c>, the handler can return any object,
        /// an error, or null.
        /// </item>
        /// </list>
        /// Defining a nested Poco (and registering it thanks to the <see cref="Setup.AlsoRegisterTypeAttribute"/>) makes
        /// it non extensible (and this is a good thing).
        /// </summary>
        [ExternalName( "CrisExecutorPayload" )]
        public interface ICrisExecutorPayload : IPoco
        {
            /// <summary>
            /// Gets or sets the execution result.
            /// </summary>
            object? Result { get; set; }
        }

        private protected CrisExecutor()
        {
            _channel = Channel.CreateUnbounded<object?>();
            _parallelRunnerCountChanged = new PerfectEventSender<ICrisExecutor>();
            _runnerCount = 1;
            _plannedRunnerCount = 1;
            _last = new Runner( this, 0, null );
        }

        /// <inheritdoc />
        public abstract string EndpointRequestTypeName { get; }

        /// <inheritdoc />
        public int ParrallelRunnerCount
        {
            get => _runnerCount;
            set
            {
                Throw.CheckOutOfRangeArgument( value >= 1 && value <= 1000 );
                Push( value );
            }
        }

        /// <inheritdoc />
        public PerfectEvent<ICrisExecutor> ParrallelRunnerCountChanged => _parallelRunnerCountChanged.PerfectEvent;

        private protected void Push( object job ) => _channel.Writer.TryWrite( job );

        private protected virtual ValueTask ExecuteTypedJobAsync( IActivityMonitor monitor, object job )
        {
            if( job is int count )
            {
                return HandleSetRunnerCountAsync( monitor, count );
            }
            monitor.Error( $"Unhandled job type '{job.GetType()}'." );
            return default;
        }

    }
}
