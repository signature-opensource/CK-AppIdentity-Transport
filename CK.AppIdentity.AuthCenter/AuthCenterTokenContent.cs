using CK.Core;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// The content of a token read by <see cref="CrisAuthCenter.ReadTokenAsync"/>.
/// </summary>
/// <param name="Info">The authentication.</param>
/// <param name="SessionId">The session identifier.</param>
/// <param name="BindingSecretHash">The hash of the binding secret of the session: the endpoints check that the caller presents it.</param>
/// <param name="SessionParty">
/// The full name of the party that opened the session (the one that serves the user's client application): only this
/// party may present the token at the Critical level to another party.
/// </param>
public sealed record AuthCenterTokenContent( AuthenticationInfo Info, string SessionId, byte[] BindingSecretHash, string SessionParty );
