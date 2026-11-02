using System;
using System.Threading.Tasks;

namespace CK.Testing.AppIdentity.Cris;

/// <summary>
/// A running "Test/$Sender" and its running "Test/$Listener", created by
/// <see cref="RunningApplication.CreatePairAsync"/>. Disposing it disposes both (the sender first).
/// </summary>
public sealed class RunningApplicationPair : IAsyncDisposable
{
    internal RunningApplicationPair( RunningApplication sender, RunningApplication listener )
    {
        Sender = sender;
        Listener = listener;
    }

    /// <summary>
    /// Gets the "Test/$Sender" application.
    /// </summary>
    public RunningApplication Sender { get; }

    /// <summary>
    /// Gets the "Test/$Listener" application.
    /// </summary>
    public RunningApplication Listener { get; }

    /// <summary>
    /// Deconstructs this pair.
    /// </summary>
    /// <param name="sender">The sender.</param>
    /// <param name="listener">The listener.</param>
    public void Deconstruct( out RunningApplication sender, out RunningApplication listener )
    {
        sender = Sender;
        listener = Listener;
    }

    /// <summary>
    /// Disposes the sender and then the listener.
    /// </summary>
    /// <returns>The awaitable.</returns>
    public async ValueTask DisposeAsync()
    {
        await Sender.DisposeAsync().ConfigureAwait( false );
        await Listener.DisposeAsync().ConfigureAwait( false );
    }
}
