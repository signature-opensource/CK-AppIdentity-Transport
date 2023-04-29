using CK.Core;
using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace CK.Cris
{

    public abstract partial class CrisExecutor<T>
    {

        ValueTask HandleSetRunnerCountAsync( IActivityMonitor monitor, int count )
        {
            int delta;
            lock( _channel )
            {
                if( _plannedRunnerCount == 0 )
                {
                    if( count != 0 ) monitor.Warn( $"BackgroundExecutor is stopping: cannot change the active runner count." );
                    return default;
                }
                delta = count - _plannedRunnerCount;
                _plannedRunnerCount = count;
            }
            if( delta < 0 )
            {

                monitor.Info( $"Decreasing active runners count from {_plannedRunnerCount} to {count} ({_runnerCount} running). Stopping {-delta} runners." );
                while( ++delta <= 0 ) _channel.Writer.TryWrite( null );
            }
            else if( delta == 0 )
            {
                monitor.Warn( $"There is already {_plannedRunnerCount} activated runners ({_runnerCount} running)." );
            }
            else
            {
                monitor.Info( $"Increasing active runners count from {_plannedRunnerCount} to {count} ({_runnerCount} running). Creating {delta} runners." );
                while( --delta >= 0 ) _channel.Writer.TryWrite( null );
            }
            return default;
        }

        bool RunnerShouldDie( IActivityMonitor monitor, Runner runner , out bool shouldRaiseCountChanged )
        {
            shouldRaiseCountChanged = false;
            lock( _channel )
            {
                int delta = _plannedRunnerCount - _runnerCount;
                if( delta == 0 )
                {
                    Debug.Fail( $"RunnerShouldDie called and _plannedRunnerCount == _runnerCount ({_runnerCount}). This should not happen." );
                    return false;
                }
                if( delta < 0 )
                {
                    --_runnerCount;
                    Debug.Assert( (_runnerCount == 0) == (runner._prev == null && runner._next == null) );
                    if( runner._prev != null )
                    {
                        runner._prev._next = runner._next;
                    }
                    if( runner._next != null )
                    {
                        runner._next._prev = runner._prev;
                    }
                    else
                    {
                        Debug.Assert( _last == runner, "If there's no next, then we are the last." );
                        _last = runner._prev;
                        Debug.Assert( (_last == null) == (_runnerCount == 0 && _plannedRunnerCount == 0) );
                    }
                    shouldRaiseCountChanged = _plannedRunnerCount > 0 && _runnerCount == _plannedRunnerCount;
                    return true;
                }
                Debug.Assert( delta > 0 );
                Debug.Assert( _last != null, "Once the _plannedRunnerCount reached 0, it can never increase." );
                ++_runnerCount;
                ++_runnerNumber;
                monitor.Info( $"Starting new runner n°{_runnerNumber}" );
                var newOne = new Runner( this, _runnerNumber, _last );
                _last._next = newOne;
                _last = newOne;
                shouldRaiseCountChanged = _plannedRunnerCount > 0 && _runnerCount == _plannedRunnerCount;
                return false;
            }
        }

        sealed class Runner
        {
            readonly CrisExecutor<T> _executor;
            readonly IActivityMonitor _monitor;
            readonly Task _runningTask;
            readonly ChannelReader<object?> _reader;
            internal Runner? _prev;
            internal Runner? _next;

            public Runner( CrisExecutor<T> executor, int runnerNumber, Runner? previous )
            {
                _executor = executor;
                _prev = previous;
                _monitor = new ActivityMonitor( $"CrisExecutor.Runner#{runnerNumber}" );
                _reader = executor._channel.Reader;
                _runningTask = Task.Run( RunAsync );
            }

            async Task RunAsync()
            {
                Interlocked.Increment( ref _executor._runnerCount );
                for( ; ;)
                {
                    var o = await _reader.ReadAsync();
                    if( o == null )
                    {
                        bool die = _executor.RunnerShouldDie( _monitor, this, out var shouldRaiseCountChanged );
                        if( shouldRaiseCountChanged )
                        {
                            await _executor._parallelRunnerCountChanged.SafeRaiseAsync( _monitor, _executor );
                        }
                        if( die ) break;
                        continue;
                    }
                    try
                    {
                        await _executor.ExecuteTypedJobAsync( _monitor, o );
                    }
                    catch( Exception ex )
                    {
                        _monitor.Error( "Unhandled exception while executing Job.", ex );
                    }
                }
                _monitor.MonitorEnd();
                Interlocked.Decrement( ref _executor._runnerCount );
            }
        }
    }
}
