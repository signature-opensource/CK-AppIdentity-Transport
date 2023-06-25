using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace CK.AppIdentity
{

    public sealed class RemoteParty : ApplicationIdentityObject, IRemote, IParty
    {
        RemoteImpl _remote;

        internal RemoteParty( RemotePartyConfiguration configuration, ApplicationIdentityDomain domain )
            : base( configuration )
        {
            _remote = new RemoteImpl( domain, configuration.Configuration );
        }

        /// <summary>
        /// Gets the configuration object.
        /// </summary>
        public RemotePartyConfiguration Configuration => Unsafe.As<RemotePartyConfiguration>( _configuration );

        /// <summary>
        /// Gets the name of this remote party.
        /// </summary>
        public string PartyName => Configuration.PartyName;

        /// <summary>
        /// Gets the address of this party.
        /// This is null if this application cannot reach the remote: this remote must be a server that accepts the remote as a client).
        /// </summary>
        public string? Address => Configuration.Address;

        public bool IsDynamic => _remote.IsDynamic;

        public bool IsDestroyed => _remote.IsDestroyed;

        public ApplicationIdentityDomain Domain => _remote.Domain;

        public bool IsRooted => throw new System.NotImplementedException();

        public Task DestroyAsync() => _remote.DestroyAsync( null );

        public bool SetDestroyed() => _remote.SetDestroyed( null );

        void IRemote.DoSetDestroyed( bool isTop ) => _remote.DoSetDestroyed( isTop, null );


    }
}
