using CK.Core;
using System;
using System.Collections.Concurrent;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// A bounded, expiring, one use in-memory store of pending operations (remote logins, passkey ceremonies...), under a
/// random key. A restart cancels the operations in progress. Since the operations are started anonymously, the
/// <see cref="Capacity"/> bounds the memory.
/// </summary>
/// <typeparam name="T">The type of the pending items.</typeparam>
public sealed class AuthCenterPendingStore<T> where T : class
{
    readonly ConcurrentDictionary<string, (T Value, DateTime Expires)> _items;

    /// <summary>
    /// Initializes a new store.
    /// </summary>
    /// <param name="lifetime">The lifetime of an item.</param>
    /// <param name="capacity">The maximal number of items.</param>
    public AuthCenterPendingStore( TimeSpan lifetime, int capacity )
    {
        Throw.CheckArgument( lifetime > TimeSpan.Zero );
        Throw.CheckArgument( capacity > 0 );
        Lifetime = lifetime;
        Capacity = capacity;
        _items = new ConcurrentDictionary<string, (T, DateTime)>( StringComparer.Ordinal );
    }

    /// <summary>
    /// Gets the lifetime of an item.
    /// </summary>
    public TimeSpan Lifetime { get; }

    /// <summary>
    /// Gets the maximal number of items.
    /// </summary>
    public int Capacity { get; }

    /// <summary>
    /// Gets the number of items (expired ones included until a purge).
    /// </summary>
    public int Count => _items.Count;

    /// <summary>
    /// Purges the expired items and gets whether a new item can be added.
    /// </summary>
    /// <param name="utcNow">The current time.</param>
    /// <returns>True if there is room for a new item.</returns>
    public bool HasRoom( DateTime utcNow )
    {
        foreach( var (key, item) in _items )
        {
            if( item.Expires < utcNow ) _items.TryRemove( key, out _ );
        }
        return _items.Count < Capacity;
    }

    /// <summary>
    /// Adds an item if there is room for it.
    /// </summary>
    /// <param name="key">The key (random, chosen by the caller).</param>
    /// <param name="value">The item.</param>
    /// <param name="utcNow">The current time.</param>
    /// <returns>True on success, false when the store is full or the key exists.</returns>
    public bool TryAdd( string key, T value, DateTime utcNow )
    {
        Throw.CheckNotNullOrEmptyArgument( key );
        Throw.CheckNotNullArgument( value );
        return HasRoom( utcNow ) && _items.TryAdd( key, (value, utcNow + Lifetime) );
    }

    /// <summary>
    /// Takes an item (one use: it is removed whatever its expiry).
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="utcNow">The current time.</param>
    /// <param name="expired">True when the item existed but has expired.</param>
    /// <returns>The item, or null when it doesn't exist or has expired.</returns>
    public T? TryTake( string? key, DateTime utcNow, out bool expired )
    {
        expired = false;
        if( string.IsNullOrEmpty( key ) || !_items.TryRemove( key, out var item ) ) return null;
        if( item.Expires < utcNow )
        {
            expired = true;
            return null;
        }
        return item.Value;
    }
}
