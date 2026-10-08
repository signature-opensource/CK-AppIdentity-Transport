using CK.Core;
using CK.Cris;
using CK.IO.Authentication;

namespace CK.AppIdentity.Cris.AuthCenter;

static class AuthCenterResults
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

    internal static ISessionResult Failure<T>( IActivityMonitor monitor, T command, string text, string resName )
        where T : ICommand<ISessionResult>
    {
        monitor.Warn( $"Session command '{command.CrisPocoModel.PocoName}' refused: {text}" );
        return command.CreateResult( r =>
        {
            r.Success = false;
            r.UserMessages.Add( UserMessage.Error( NormalizedCultureInfo.CodeDefault, text, resName ) );
        } );
    }
}
