using CK.Core;
using CommunityToolkit.HighPerformance.Helpers;
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    /// <summary>
    /// Simple agent that always accepts jobs (basic delegates and any specifically implemented type - see the protected <see cref="PushTypedJob(object)"/>),
    /// starts once but may refuse to start, and always run (once started errors are logged but it continues its work) until the
    /// protected <see cref="SendStop"/> method is called.
    /// <para>
    /// It is rather basic but enough for our needs here and may be reused by <see cref="ApplicationIdentityFeatureDriver"/> if needed.
    /// </para>
    /// </summary>
    public abstract class MicroAgent
    {
        readonly ActivityMonitor _monitor;
        readonly Timer? _heartbeat;
        // We use null as the final close signal (after the _stopSignal instance).
        // No need for a cancellation token source.
        // We use the channel object as the lock (it is the single private object).
        readonly Channel<object?> _channel;
        readonly string _name;
        Task? _runningTask;
        RunningStatus _status;
        int _heartbeatPeriod;
        int _heartbeatCount;
        int _heartbeatReentrantCount;
        bool _inHeartBeat;

        static readonly object _heartbeatSignal = new object();
        static readonly object _stopSignal = new object();

        /// <summary>
        /// Initializes a new Micro Agent.
        /// </summary>
        /// <param name="name">The required name of this micro agent.</param>
        /// <param name="heartbeatPeriod">
        /// Optional heartbeat in milliseconds: when 0, no <see cref="Timer"/> is allocated.
        /// When positive, must be greater or equal to 20.
        /// </param>
        protected MicroAgent( string name, int heartbeatPeriod = 0 )
        {
            Throw.CheckNotNullArgument( name );
            Throw.CheckArgument( heartbeatPeriod == 0 || heartbeatPeriod >= 20 );
            _monitor = new ActivityMonitor( name );
            Debug.Assert( _monitor.ParallelLogger != null );
            _channel = Channel.CreateUnbounded<object?>( new UnboundedChannelOptions { SingleReader = true } );
            _name = name;
            if( heartbeatPeriod > 0 )
            {
                _heartbeatPeriod = heartbeatPeriod;
                _heartbeat = new Timer( OnTimer, this, Timeout.Infinite, Timeout.Infinite );
            }
        }

        static void OnTimer( object? state ) => Unsafe.As<MicroAgent>( state! ).PushTypedJob( _heartbeatSignal );

        /// <summary>
        /// The agent status.
        /// </summary>
        public enum RunningStatus
        {
            /// <summary>
            /// The agent is waiting to be successfully started.
            /// </summary>
            WaitingForStart,

            /// <summary>
            /// The agent is running.
            /// </summary>
            Running,

            /// <summary>
            /// The agent is dead. It has been stopped by a call to <see cref="SendStop()"/>.
            /// </summary>
            Stopped
        }

        /// <summary>
        /// Gets the running status of this agent.
        /// </summary>
        public RunningStatus Status => _status;

        /// <summary>
        /// Gets this micro agent logger.
        /// </summary>
        public IParallelLogger Logger => _monitor.ParallelLogger!;

        /// <summary>
        /// Executes a synchronous action on the agent loop. The goal is to avoid any closure in the action: the <paramref name="arg"/>
        /// should contain all parameters of the action. 
        /// </summary>
        /// <typeparam name="T">The type of the argument.</typeparam>
        /// <param name="arg">The argument to the action. Should be a static lambda if possible.</param>
        /// <param name="action">The action to execute.</param>
        public void PostAction<T>( in T arg, Action<IActivityMonitor, T> action ) => _channel.Writer.TryWrite( new Job<T>( arg, action ) );

        /// <summary>
        /// Executes an asynchronous action on the agent loop. The goal is to avoid any closure in the action: the <paramref name="arg"/>
        /// should contain all parameters of the action. 
        /// </summary>
        /// <typeparam name="T">The type of the argument.</typeparam>
        /// <param name="arg">The argument to the action. Should be a static lambda if possible.</param>
        /// <param name="action">The action to execute.</param>
        public void PostTask<T>( in T arg, Func<IActivityMonitor, T, Task> action ) => _channel.Writer.TryWrite( new Job<T>( arg, action ) );

        /// <summary>
        /// Executes an asynchronous action on the agent loop. The goal is to avoid any closure in the action: the <paramref name="arg"/>
        /// should contain all parameters of the action. 
        /// </summary>
        /// <typeparam name="T">The type of the argument.</typeparam>
        /// <param name="arg">The argument to the action.</param>
        /// <param name="action">The action to execute. Should be a static lambda if possible.</param>
        public void PostValueTask<T>( in T arg, Func<IActivityMonitor, T, ValueTask> action ) => _channel.Writer.TryWrite( new Job<T>( arg, action ) );

        /// <summary>
        /// Pushes an object that must be handled by <see cref="ExecuteTypedJobAsync(IActivityMonitor, object)"/>.
        /// </summary>
        /// <param name="job">The job to execute.</param>
        protected void PushTypedJob( object job )
        {
            Throw.CheckNotNullArgument( job );
            _channel.Writer.TryWrite( job );
        }

        /// <summary>
        /// Gets whether the provided monitor is the one of this micro agent.
        /// </summary>
        /// <param name="monitor">The monitor to check.</param>
        /// <returns>True if this is our monitor.</returns>
        public bool IsInLoop( IActivityMonitor monitor ) => monitor == _monitor;

        /// <summary>
        /// Tries to start this agent. This can succeed only once but
        /// may fail to start multiple times: <see cref="OnTryStart(IActivityMonitor)"/>
        /// can be overridden to check any running preconditions.
        /// </summary>
        /// <returns>
        /// The running status. When <see cref="RunningStatus.Stopped"/>, another agent
        /// should be instantiated.
        /// </returns>
        protected RunningStatus TryStart()
        {
            lock( _channel )
            {
                if( _status != RunningStatus.WaitingForStart ) return _status;
                if( !OnTryStart( _monitor ) )
                {
                    return _status;
                }
                _heartbeat?.Change( _heartbeatPeriod, _heartbeatPeriod );
                _status = RunningStatus.Running;
                _runningTask = Task.Run( RunAsync );
                return _status;
            }
        }

        interface IJob
        {
            Task ExecuteAsync( IActivityMonitor monitor );
        }

        sealed class Job<T> : IJob
        {
            readonly T _arg;
            readonly object _action;
            int _type;

            public Job( in T arg, Action<IActivityMonitor, T> action )
            {
                _arg = arg;
                _action = action;
            }

            public Job( in T arg, Func<IActivityMonitor, T, Task> action )
            {
                _arg = arg;
                _action = action;
                _type = 1;
            }

            public Job( in T arg, Func<IActivityMonitor, T, ValueTask> action )
            {
                _arg = arg;
                _action = action;
                _type = 2;
            }

            Task IJob.ExecuteAsync( IActivityMonitor monitor )
            {
                switch( _type )
                {
                    case 0:
                        Unsafe.As<Action<IActivityMonitor, T>>( _action )( monitor, _arg );
                        return Task.CompletedTask;
                    case 1:
                        return Unsafe.As<Func<IActivityMonitor, T, Task>>( _action )( monitor, _arg );
                    default:
                        return Unsafe.As<Func<IActivityMonitor, T, ValueTask>>( _action )( monitor, _arg ).AsTask();
                }
            }
        }

        async Task RunAsync()
        {
            try
            {
                await OnStartAsync( _monitor );
            }
            catch( Exception ex )
            {
                _monitor.Error( "Error while starting the agent.", ex );
            }
            // We pool the channel until the null final closing signal.
            object? o;
            while( (o = await _channel.Reader.ReadAsync()) != null )
            {
                try
                {
                    if( o == _stopSignal )
                    {
                        using( _monitor.OpenInfo( $"Stopping {ToString()}." ) )
                        {
                            // The heartbeat is disposed when sending the stop signal.
                            await OnStopAsync( _monitor );
                            if( _channel.Writer.TryWrite( null ) ) _channel.Writer.TryComplete();
                        }
                    }
                    else if( o == _heartbeatSignal )
                    {
                        // This is mainly when debugging. In practice, heart beat handling
                        // should not be longer than 1 second.
                        if( _inHeartBeat )
                        {
                            ++_heartbeatReentrantCount;
                            if( !Debugger.IsAttached )
                            {
                                _monitor.Warn( $"Heartbeat blocked for {_heartbeatReentrantCount} count." );
                            }
                        }
                        else
                        {
                            _heartbeatReentrantCount = 0;
                            _inHeartBeat = true;
                            try
                            {
                                await OnHeartbeatAsync( _monitor, _heartbeatCount++ );
                            }
                            catch( Exception ex )
                            {
                                _monitor.Error( $"{_name}'s heartbeat unhandled error.", ex );
                            }
                            _inHeartBeat = false;
                        }
                    }
                    else if( o is IJob job )
                    {
                        await job.ExecuteAsync( _monitor );
                    }
                    else
                    {
                        await ExecuteTypedJobAsync( _monitor, o );
                    }
                }
                catch( Exception ex )
                {
                    if( o == _stopSignal )
                    {
                        _monitor.Error( "Unhandled exception while stopping.", ex );
                        if( _channel.Writer.TryWrite( null ) )  _channel.Writer.TryComplete();
                    }
                    else
                    {
                        _monitor.Error( "Unhandled exception while executing Job.", ex );
                    }
                }
            }
            _monitor.MonitorEnd();
        }

        /// <summary>
        /// Emits "Unhandled job type" log error.
        /// </summary>
        /// <param name="monitor">The monitor.</param>
        /// <param name="job">The unknown job.</param>
        protected virtual ValueTask ExecuteTypedJobAsync( IActivityMonitor monitor, object job )
        {
            monitor.Error( $"Unhandled job type '{job.GetType():C}'." );
            return default;
        }

        /// <summary>
        /// Called by <see cref="TryStart(CancellationToken)"/>.
        /// When this returns true, The agent is <see cref="RunningStatus.Running"/>.
        /// Any exception raised here is raised by TryStart and the agent is let in <see cref="RunningStatus.WaitingForStart"/> state.
        /// </summary>
        /// <param name="monitor">The agent monitor.</param>
        /// <returns>True allow the agent to run, false to prevent it to start.</returns>
        protected virtual bool OnTryStart( IActivityMonitor monitor ) => true;

        /// <summary>
        /// Optional heartbeat implementation. Exceptions are caught and logged, reentrancy
        /// is already checked.
        /// <para>
        /// Does nothing by default.
        /// </para>
        /// </summary>
        /// <param name="monitor">The agent's monitor.</param>
        /// <param name="callCount">The current call count. Starts at 0.</param>
        /// <returns>The awaitable.</returns>
        protected virtual Task OnHeartbeatAsync( IActivityMonitor monitor, int callCount ) => Task.CompletedTask;

        /// <summary>
        /// Called at the start of the running the loop.
        /// Any exception raised here is logged and the agent keeps running.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <returns>The awaitable.</returns>
        protected virtual ValueTask OnStartAsync( IActivityMonitor monitor ) => default;

        /// <summary>
        /// Sends the stop signal that triggers the call to <see cref="OnStopAsync(IActivityMonitor)"/>.
        /// Use <see cref="RunningTask"/> to wait for completion.
        /// <para>
        /// An agent can successfully start only once.
        /// </para>
        /// </summary>
        /// <returns>True if this call triggered the stop, false if it is already stopped or is not started.</returns>
        internal protected bool SendStop()
        {
            lock( _channel )
            {
                if( _status == RunningStatus.Running )
                {
                    _heartbeat?.Dispose();
                    _status = RunningStatus.Stopped;
                    _channel.Writer.TryWrite( _stopSignal );
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Called at the end of the running the loop. This can push new actions and
        /// will eventually stop this agent and signal the <see cref="RunningTask"/>.
        /// Does nothing at this level.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <returns>The awaitable.</returns>
        protected virtual ValueTask OnStopAsync( IActivityMonitor monitor ) => default;

        /// <summary>
        /// Gets a task that is completed if this agent is not yet started or if it has run.
        /// </summary>
        public Task RunningTask => _runningTask ?? Task.CompletedTask;

        /// <summary>
        /// Overridden to return the <see cref="Name"/> of this agent that is the
        /// initial <see cref="Monitor"/>'s <see cref="IActivityMonitor.Topic"/>.
        /// </summary>
        /// <returns>This agent's name.</returns>
        public override sealed string ToString() => _name;
    }
}
