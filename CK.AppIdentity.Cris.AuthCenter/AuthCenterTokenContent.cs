using CK.Core;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// The content of a token read by <see cref="CrisAuthCenter.ReadTokenAsync"/>.
/// </summary>
/// <param name="Info">The authentication.</param>
/// <param name="SessionId">The session identifier.</param>
/// <param name="BindingSecretHash">The hash of the binding secret of the session: the endpoints check that the caller presents it.</param>
public sealed record AuthCenterTokenContent( AuthenticationInfo Info, string SessionId, string BindingSecretHash );
