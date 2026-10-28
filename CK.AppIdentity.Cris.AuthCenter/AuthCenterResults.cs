using CK.Core;
using CK.Cris;
using CK.IO.Authentication;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// Builds the results of the session operations. Public for the scheme family packages, that handle their own operations.
/// The source is the Cris Poco being handled (an operation, or the session command it carries): it is used to log and to
/// reach the <see cref="PocoDirectory"/>.
/// </summary>
public static class AuthCenterResults
{
    /// <summary>
    /// Creates a successful session result.
    /// </summary>
    /// <param name="source">The handled Cris Poco.</param>
    /// <param name="info">The authentication of the session.</param>
    /// <param name="token">The signed token.</param>
    /// <param name="rememberMe">Whether the session survives the end of the caller session.</param>
    /// <returns>The session result.</returns>
    public static ISessionResult Success( ICrisPoco source, AuthenticationInfo info, string token, bool rememberMe )
    {
        return Directory( source ).Create<ISessionResult>( r =>
        {
            r.Info.InitializeFrom( info );
            r.Token = token;
            r.RememberMe = rememberMe;
        } );
    }

    /// <summary>
    /// Creates a failed session result (a decision of the Authentication Center).
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="source">The handled Cris Poco.</param>
    /// <param name="text">The error text.</param>
    /// <param name="resName">The error resource name.</param>
    /// <returns>The session result.</returns>
    public static ISessionResult Failure( IActivityMonitor monitor, ICrisPoco source, string text, string resName )
    {
        return Failure<ISessionResult>( monitor, source, text, resName );
    }

    /// <summary>
    /// Creates a failed standard result (a decision of the Authentication Center).
    /// </summary>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="source">The handled Cris Poco.</param>
    /// <param name="text">The error text.</param>
    /// <param name="resName">The error resource name.</param>
    /// <returns>The result.</returns>
    public static TResult Failure<TResult>( IActivityMonitor monitor, ICrisPoco source, string text, string resName )
        where TResult : class, IStandardResultPart
    {
        monitor.Warn( $"'{source.CrisPocoModel.PocoName}' refused: {text}" );
        return Directory( source ).Create<TResult>( r =>
        {
            r.Success = false;
            r.UserMessages.Add( UserMessage.Error( NormalizedCultureInfo.CodeDefault, text, resName ) );
        } );
    }

    static PocoDirectory Directory( ICrisPoco source ) => ((IPocoGeneratedClass)source).Factory.PocoDirectory;
}
