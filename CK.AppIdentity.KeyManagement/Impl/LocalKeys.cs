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

    internal void OnTearDown( IActivityMonitor monitor )
    {
        var identities = _identities;
        foreach( var key in identities )
        {
            key.OnTeardown();
        }
    }
}
