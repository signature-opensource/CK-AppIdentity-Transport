using CK.Core;
using CK.Cris;
using CK.IO.Authentication;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// Builds the results of the session commands. Public for the scheme family packages, that handle their own commands.
/// </summary>
public static class AuthCenterResults
{
    internal static ISessionResult Success<T>( T command, AuthenticationInfo info, string token, bool rememberMe )
        where T : ICommand<ISessionResult>
    {
        return command.CreateResult( r =>
        {
            r.Info.InitializeFrom( info );
            r.Token = token;
            r.RememberMe = rememberMe;
        } );
    }

    /// <summary>
    /// Creates a failed result (no token): the error is a user message, and it is logged.
    /// </summary>
    /// <typeparam name="T">The command type.</typeparam>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The refused command.</param>
    /// <param name="text">The error text.</param>
    /// <param name="resName">The resource name of the error.</param>
    /// <returns>The failed result.</returns>
    public static ISessionResult Failure<T>( IActivityMonitor monitor, T command, string text, string resName )
        where T : ICommand<ISessionResult>
    {
        return Failure<T, ISessionResult>( monitor, command, text, resName );
    }

    /// <summary>
    /// Creates a failed <see cref="IStandardResultPart"/> result: the error is a user message, and it is logged.
    /// </summary>
    /// <typeparam name="T">The command type.</typeparam>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="command">The refused command.</param>
    /// <param name="text">The error text.</param>
    /// <param name="resName">The resource name of the error.</param>
    /// <returns>The failed result.</returns>
    public static TResult Failure<T, TResult>( IActivityMonitor monitor, T command, string text, string resName )
        where T : ICommand<TResult>
        where TResult : class, IStandardResultPart
    {
        monitor.Warn( $"Session command '{command.CrisPocoModel.PocoName}' refused: {text}" );
        return command.CreateResult( r =>
        {
            r.Success = false;
            r.UserMessages.Add( UserMessage.Error( NormalizedCultureInfo.CodeDefault, text, resName ) );
        } );
    }
}
