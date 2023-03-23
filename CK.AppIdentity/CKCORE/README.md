# basicTrampoline

The Trampoline pattern is a form of continuations: a function can post another function that must be executed later.
Later means after any of potential continuation previously emitted by other functions.

The [`BasicTrampoline`](BasicTrampoline.cs) is a registrar of parameterless actions: the execution context needed for
actions to be executed must be provided by closure. These actions that can be
synchronous (`Action`) or asynchronous (`Func<Task>` or `Func<ValueTask>`). Since relying on exception
is not a very good practice, actions can also returns a gentle boolean instead of only throwing on error:
a `Func<bool>`, `Func<Task<bool>>` or `Func<ValueTask<bool>>` action that returns false is considered on error.

There are 4 categories of actions:
- Initial actions are the root actions that must be executed sequentially. Those are the ones that can return a
gentle false boolean.

The 3 other categories should not fail (no boolean returns are supported for them):
- Success handlers are called when all initial actions have been successfully executed.
- Error handlers are all called on the first initial failing action.
These handlers are meant to "compensate on error". Error handlers should be registered by successful initial actions
so that if any error happens after them, their own impacts can be reversed/canceled.
- Finally handlers are always called after success or error handlers.

The [`BasicTrampolineRunner`](BasicTrampolineRunner.cs) is in charge of executing the registered actions of
a BasicTrampoline thanks to 2 methods:

```csharp
public Task ExecuteAsync( IActivityMonitor monitor );
public Task ExecuteAllAsync( IActivityMonitor monitor );
```

Often the `ExecuteAsync` that stops on the first error is fine, but if the wanted behavior is to execute all
the actions even if some of them fails (when one want to collect multiple errors from a complex process rather
than only the very first one), `ExecuteAllAsync` can be used.

Success, Error and Finally handlers should not throw. If they do, the exception is logged but the process continues.
Such hidden errors are reported by the exposed `Result` (and appear in the logs of course).

A runner can be executed only once. It exposes its execution result:
- The `BasicTrampoline` than can be used by actions to register other actions to be executed.
- An optional `IDictionary<object, object> Memory` that can be used by actions to share any state.
- The current `Result` and `Error`.



