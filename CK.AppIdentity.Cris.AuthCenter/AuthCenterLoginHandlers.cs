using CK.Auth;
using CK.Core;
using CK.Cris;
using CK.IO.Authentication;
using CK.IO.Authentication.Basic;
using CK.IO.Authentication.Weak;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter;

// TEMPORARY HOME. "A package that implements an authentication provider handles its login commands": these handlers
// belong to CK.DB.User.UserPassword (Basic) and CK.DB.Actor.WeakActor (Weak). They are here only because these DB packages
// are also used by the old authentication stack, and a handler needs CK.Cris.Authentication, which defines the same
// CK.Auth.CrisAuthenticationService as the old CK.Cris.Auth (CS0433 in the generated code of an old-stack application).
// WHEN THE OLD STACK IS RETIRED, THESE HANDLERS MUST GO BACK TO THEIR DB PACKAGES (and the AuthCenter must stop
// knowing the Basic and Weak commands).

/// <summary>
/// Handles the <see cref="IBasicLoginCommand"/>: the session is opened with a <see cref="BasicLoginPayload"/> by the
/// "Basic" <see cref="ILoginProvider"/> (CK.DB.User.UserPassword for instance).
/// <para>
/// This handler is here until the old authentication stack is retired: it then moves to CK.DB.User.UserPassword.
/// </para>
/// </summary>
public sealed class AuthCenterBasicLoginHandler : ISingletonAutoService
{
    /// <summary>
    /// Handles the <see cref="IBasicLoginCommand"/>.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="cmd">The command.</param>
    /// <param name="opener">The session opener.</param>
    /// <returns>The session result.</returns>
    [CommandHandler]
    public ValueTask<ISessionResult> HandleAsync( IActivityMonitor monitor, IBasicLoginCommand cmd, IAuthenticationSessionOpener opener )
    {
        return opener.OpenSessionAsync( monitor, cmd, BasicLoginPayload.Scheme, new BasicLoginPayload( cmd.UserName, cmd.Password ), cmd.RememberMe );
    }
}

/// <summary>
/// Handles the <see cref="IWeakLoginCommand"/>: its payload is the command itself, for the "Weak"
/// <see cref="ILoginProvider"/> (CK.DB.Actor.WeakActor for instance).
/// <para>
/// When a package extends the command (CK.IO.Authentication.WeakZone), this handler is ignored: the extending package
/// handles the whole command (CK.DB.Zone.WeakActor).
/// </para>
/// <para>
/// This handler is here until the old authentication stack is retired: it then moves to CK.DB.Actor.WeakActor.
/// </para>
/// </summary>
public sealed class AuthCenterWeakLoginHandler : ISingletonAutoService
{
    /// <summary>
    /// Handles the <see cref="IWeakLoginCommand"/>.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="cmd">The command.</param>
    /// <param name="opener">The session opener.</param>
    /// <returns>The session result.</returns>
    [CommandHandler]
    public ValueTask<ISessionResult> HandleAsync( IActivityMonitor monitor, IWeakLoginCommand cmd, IAuthenticationSessionOpener opener )
    {
        return opener.OpenSessionAsync( monitor, cmd, ActorInfo.WeakScheme, cmd );
    }
}
