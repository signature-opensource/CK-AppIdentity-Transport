namespace CK.AppIdentity.Cris
{

    public sealed class RemoteCommandExecutor
    {
        readonly AppIdentityAgent _appIdentityAgent;
        readonly IRemoteParty _remote;

        public RemoteCommandExecutor( AppIdentityAgent appIdentityAgent, IRemoteParty remote )
        {
            _appIdentityAgent = appIdentityAgent;
            _remote = remote;
        }
    }
}
