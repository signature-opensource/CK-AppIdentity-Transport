using CK.Core;
using Microsoft.AspNetCore.DataProtection;
using System.Collections.Generic;

namespace CK.AppIdentity.KeyManagement;

sealed partial class LocalKeys : ILocalKeys
{
    const string PasswordExtension = ".pwd";
    readonly ILocalParty _local;
    readonly IDataProtector _protector;
    readonly int _allowedOfflineDays;
    // Key renewal should be implemented while running soon:
    // this is not readonly (Interlocked exchanged).
    // This must be an array (not the ImmutableArray) so that
    // reference equality can be used to detect changes.
    LocalIdentityKey[] _identities;

    LocalKeys( ILocalParty local,
               IDataProtector protector,
               LocalIdentityKey[] identities,
               int allowedOfflineDays )
    {
        _local = local;
        _identities = identities;
        _allowedOfflineDays = allowedOfflineDays;
        _protector = protector;
    }

    public ILocalParty Party => _local;

    public int AllowedOfflineDays => _allowedOfflineDays;

    public IDataProtector Protector => _protector;

    public LocalIdentityKey CurrentIdentity => _identities[0];

    public IReadOnlyList<LocalIdentityKey> Identities => _identities;

    /// <summary>
    /// Disposes every identity key of this local party.
    /// <para>
    /// Known and accepted: a negotiation still in flight can be inside
    /// <see cref="LocalIdentityKey.TrySignHash"/> on one of these when this runs, and will then throw
    /// <see cref="ObjectDisposedException"/> into its back task, where it is caught and logged. This
    /// is reached only when the whole service is shutting down or the local party is being destroyed,
    /// so the connection that fails was about to be torn down anyway. Making it airtight means
    /// reference-counting every signing operation — real complexity, paid on every handshake, to
    /// avoid a logged exception on a path that is already ending. Not disposing at all is worse: this
    /// also runs on party destruction in a long-lived process, and those keys must go.
    /// </para>
    /// </summary>
    internal void OnTearDown( IActivityMonitor monitor )
    {
        var identities = _identities;
        foreach( var key in identities )
        {
            key.OnTeardown();
        }
    }
}
