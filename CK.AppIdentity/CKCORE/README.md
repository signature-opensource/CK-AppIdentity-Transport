# Trampoline

The Trampoline pattern is a form of continuations: a function can post another function that must be executed later.
Later means after any of potential continuation previously emitted by other functions.

The [`Trampoline<T>`](Trampoline.cs) is a registrar of actions that accepts `T` as their only parameter: this `T` is the
execution context that must provide all that is needed for actions to be executed. These actions that can be
synchronous (`Action<T>`) or asynchronous (`Func<T,Task>` or `Func<T,ValueTask>`). Since relying on exception
is not a very good practice, actions can also returns a gentle boolean instead of only throwing on error:
an `Action<T,bool>`, `Func<T,Task<bool>>` or `Func<T,ValueTask<bool>>` that returns false is considered on error.

There are 4 categories of actions:
- Initial actions are the root actions that must be executed sequentially. Those are the ones that can return a
gentle false boolean.

The 3 other categories should not fail (no boolean returns are supported for them):
- Success handlers are called when all initial actions have been successfully executed.
- Error handlers (accepts a secondary Exception parameter) are all called on the first initial failing action.
These handlers are meant to "compensate on error". Error handlers should be registered by successful initial actions
so that if any error happens after them, their own impacts can be reversed/canceled.
- Finally handlers are always called after success or error handlers.

The [`TrampolineRunner<TSelf>`](TrampolineRunner{TSelf}.cs) is in charge of executing the registered actions of
a Trampoline thanks to a single method that returns a simple Result:

```csharp
/// <summary>
/// Captures <see cref="ExecuteAsync(bool)"/> result.
/// </summary>
public enum Result
{
    /// <summary>
    /// No exception at all have been thrown.
    /// </summary>
    TotalSuccess,

    /// <summary>
    /// An action thrown an exception. Error and finally handlers have been called. 
    /// </summary>
    Error = 1,

    /// <summary>
    /// At least one success handler thrown an exception.
    /// </summary>
    HasSuccessException = 2,

    /// <summary>
    /// At least one error handler thrown an exception.
    /// </summary>
    HasErrorException = 4,

    /// <summary>
    /// At least one finally handler thrown an exception.
    /// </summary>
    HasFinallyException = 8,
}

public async Task<Result> ExecuteAsync( bool reverseInitialActions = false );
```

Success, Error and Finally handlers should not throw. If they do, the exception is logged but the process continues.
Such hidden errors are reported by the final `Result` (and appear in the logs of course).

A `TrampolineRunner<TSelf>` is built on a `IActivityMonitor`. This is a pattern that should commonly be avoided but
that makes sens here: the runner must be used locally in an activity, it is the execution context with which
all the actions will interact during the `ExecuteAsync` run and it exposes by default:
- The Monitor to use.
- The `Trampoline<T>` where T is itself than can be used by actions to register other actions to be executed.
- An optional `IDictionary<object, object> Memory` that can be used by actions to share any state.
- The current `Result`.

A runner can be executed only once. If it not executed, it should be disposed in order to dispose any
disposable objects registered in its shared `Memory`.

## Not stopping on the first error
Rarely, the wanted behavior is to execute all the actions even if some of them fails. This can be the
case when one want to collect multiple errors from a complex process rather than only the very first one.
For this, one can use the `ExecuteAllAsync` method:

```csharp
/// <summary>
/// Executes all the currently enlisted actions (optionally in reverse order) regardless of whether they fail or not
/// and returns null on success.
/// On error the single exception or an <see cref="AggregateException"/> with multiple exceptions is returned.
/// <para>
/// Note that during the execution, <see cref="StopOnFirstError"/> and the <see cref="CurrentResult"/> are available:
/// an action can know that it is being executed in this mode and that one or more previous actions have failed.
/// </para>
/// </summary>
/// <param name="reverseInitialActions">
/// True to revert the initial action list: the last registered action will be the first to be called.
/// </param>
/// <returns>Null on success otherwise the single exception or an <see cref="AggregateException"/> with multiple exceptions.</returns>
public Task<Exception?> ExecuteAllAsync( bool reverseInitialActions = false );
```

