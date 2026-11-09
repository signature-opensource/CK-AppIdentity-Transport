using CK.AppIdentity.KeyManagement;
using CK.AppIdentity.TransportLayer;
using CK.Core;
using System;
using System.Threading.Tasks;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// The <see cref="ICrisAuthCenter"/> feature (see <see cref="AuthCenterFeature"/>). A single instance is shared by a
/// <see cref="ILocalParty"/> and its <see cref="ILocalParty.Remotes"/> that allow "AuthCenterRemote": the remotes that use it
/// when the local party is the Authentication Center, the remote that is its Authentication Center otherwise.
/// <para>
/// This is the part shared by the two sides: the Local side (CK.AppIdentity.AuthCenter.Local) creates it for a local party
/// that is the Authentication Center and adds a <c>LocalAuthCenter</c>, the Remote side (CK.AppIdentity.AuthCenter.Remote)
/// creates it for a local party that uses a remote one and adds a <c>RemoteAuthCenter</c>.
/// </para>
/// </summary>
public sealed class CrisAuthCenter : ICrisAuthCenter
{
    readonly ILocalParty _owner;
    readonly IParty _authCenter;

    internal CrisAuthCenter( ILocalParty owner, IParty authCenter )
    {
        Throw.DebugAssert( authCenter == owner || (authCenter is IRemoteParty r && r.Owner == owner) );
        _owner = owner;
        _authCenter = authCenter;
    }

    /// <summary>
    /// Creates the feature of a local party and adds it to the local party (and to the <paramref name="authCenter"/> when it
    /// is a remote). The Authentication Center must have the "KeyManagement" feature: its keys verify the tokens (a remote
    /// may not be pinned yet: the verification refuses until it is). Used by the two sides of the feature.
    /// </summary>
    /// <param name="monitor">The monitor.</param>
    /// <param name="owner">The local party.</param>
    /// <param name="authCenter">The local party itself, or the remote that is its Authentication Center.</param>
    /// <returns>The feature or null on error.</returns>
    public static CrisAuthCenter? TryCreate( IActivityMonitor monitor, ILocalParty owner, IParty authCenter )
    {
        Throw.CheckArgument( authCenter == owner || (authCenter is IRemoteParty r && r.Owner == owner) );
        if( authCenter.GetFeature<IPartyKeys>() == null )
        {
            monitor.Error( $"'{authCenter}' cannot be the AuthCenter of '{owner}': it has no 'KeyManagement' feature (its keys verify the tokens)." );
            return null;
        }
        var f = new CrisAuthCenter( owner, authCenter );
        owner.AddFeature( f );
        if( authCenter != owner ) authCenter.AddFeature( f );
        monitor.Info( $"{f} is available." );
        return f;
    }

    /// <summary>
    /// Gets the local party for which <see cref="AuthCenter"/> is the Authentication Center.
    /// </summary>
    public ILocalParty Owner => _owner;

    /// <inheritdoc />
    public IParty AuthCenter => _authCenter;

    /// <summary>
    /// Gets whether the Authentication Center can be used. This is false when the Authentication Center
    /// is a remote that has been destroyed: authentication is unavailable for the <see cref="Owner"/> (features
    /// cannot be removed, this feature stays and fails closed).
    /// </summary>
    public bool IsAvailable => !(_authCenter is IRemoteParty r && r.IsDestroyed);

    /// <inheritdoc />
    public bool Verify( IActivityLineEmitter logger, ReadOnlySpan<byte> data, in ApplicationSignature signature )
        => Check( logger, data, signature ) == SignatureVerdict.Valid;

    /// <inheritdoc />
    public SignatureVerdict Check( IActivityLineEmitter logger, ReadOnlySpan<byte> data, in ApplicationSignature signature )
    {
        if( !IsAvailable )
        {
            logger.Warn( $"Token refused: the AuthCenter '{_authCenter}' of '{_owner}' has been destroyed." );
            return SignatureVerdict.Refused;
        }
        // The driver checked that the AuthCenter has its keys.
        return _authCenter.GetRequiredFeature<IPartyKeys>().Check( logger, ICrisAuthCenter.TokenPurpose, data, signature );
    }

    /// <summary>
    /// The maximal time <see cref="ReadTokenAsync"/> waits for the key events of a remote Authentication Center: 2 seconds.
    /// </summary>
    public static readonly TimeSpan KeyEventsTimeout = TimeSpan.FromSeconds( 2 );

    /// <summary>
    /// Reads a token issued by the Authentication Center: its signature is verified (see <see cref="Check"/>), then its
    /// expiration and its audience: the <see cref="AuthCenter"/> party (a token issued by another Authentication Center, of
    /// another tenant domain for instance, is refused). The authentication cannot outlive the token.
    /// <para>
    /// For a remote Authentication Center, when the signature is refused because its issuer is not known here (it rotated
    /// its key and its key events, normally pushed, have not been received), the key events are requested (at most
    /// <see cref="KeyEventsTimeout"/>) and the token is read again, once.
    /// </para>
    /// </summary>
    /// <param name="logger">Receives the reason of a refusal.</param>
    /// <param name="token">The token.</param>
    /// <param name="utcNow">The current time.</param>
    /// <returns>The token content, or null if the token is refused.</returns>
    public async ValueTask<AuthCenterTokenContent?> ReadTokenAsync( IActivityLineEmitter logger, string token, DateTime utcNow )
    {
        Throw.CheckNotNullArgument( token );
        var verdict = AuthCenterToken.Read( logger, this, _authCenter.FullName, token, utcNow, out var info, out var sessionParty, out var sessionId, out var bindingSecretHash );
        if( verdict == SignatureVerdict.UnknownIssuer
            && _authCenter.GetFeature<TransportFeature>() is TransportFeature transport
            && await transport.RequestKeyEventsAsync( KeyEventsTimeout ).ConfigureAwait( false ) )
        {
            verdict = AuthCenterToken.Read( logger, this, _authCenter.FullName, token, utcNow, out info, out sessionParty, out sessionId, out bindingSecretHash );
        }
        return verdict == SignatureVerdict.Valid ? new AuthCenterTokenContent( info!, sessionId!, bindingSecretHash!, sessionParty! ) : null;
    }

    /// <summary>
    /// Reads a user's proof (a token and the hash of the binding secret presented with it): the token is read (see
    /// <see cref="ReadTokenAsync"/>) and the binding secret must be the one of its session. This is local: the liveness
    /// of the session is not checked (see <see cref="IAuthCenterProofChecker"/>).
    /// <para>
    /// A party relays a proof only after this reading: a proof that fails it is evidence against the party that sent it.
    /// </para>
    /// </summary>
    /// <param name="logger">Receives the reason of a refusal.</param>
    /// <param name="token">The token.</param>
    /// <param name="bindingSecretHash">The hash of the binding secret presented with the token.</param>
    /// <param name="utcNow">The current time.</param>
    /// <returns>The token content, or null if the proof is refused.</returns>
    public async ValueTask<AuthCenterTokenContent?> ReadProofAsync( IActivityLineEmitter logger, string token, byte[]? bindingSecretHash, DateTime utcNow )
    {
        Throw.CheckNotNullArgument( token );
        if( bindingSecretHash == null )
        {
            logger.Warn( "A user's token without the binding secret of its session is refused." );
            return null;
        }
        var read = await ReadTokenAsync( logger, token, utcNow ).ConfigureAwait( false );
        if( read == null ) return null;
        if( !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals( bindingSecretHash, read.BindingSecretHash ) )
        {
            logger.Warn( "A user's token with another binding secret than the one of its session is refused." );
            return null;
        }
        return read;
    }

    // Checks a signature of the AuthCenter for a purpose, with the safety net of a remote AuthCenter (see ReadTokenAsync).
    internal async ValueTask<SignatureVerdict> CheckWithKeyEventsAsync( IActivityLineEmitter logger, string purpose, byte[] data, ApplicationSignature signature )
    {
        if( !IsAvailable ) return SignatureVerdict.Refused;
        var keys = _authCenter.GetRequiredFeature<IPartyKeys>();
        var verdict = keys.Check( logger, purpose, data, signature );
        if( verdict == SignatureVerdict.UnknownIssuer
            && _authCenter.GetFeature<TransportFeature>() is TransportFeature transport
            && await transport.RequestKeyEventsAsync( KeyEventsTimeout ).ConfigureAwait( false ) )
        {
            verdict = keys.Check( logger, purpose, data, signature );
        }
        return verdict;
    }

    /// <summary>
    /// Overridden to return the Authentication Center and its owner.
    /// </summary>
    /// <returns>A readable string.</returns>
    public override string ToString() => _authCenter == _owner ? $"AuthCenter '{_owner}' (local)" : $"AuthCenter '{_authCenter}' (remote of '{_owner}')";
}
