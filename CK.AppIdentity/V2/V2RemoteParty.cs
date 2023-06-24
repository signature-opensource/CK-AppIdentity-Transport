using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace CK.AppIdentity
{

    public sealed class V2RemoteParty : V2AppIdentityObject, V2IRemote, V2IParty
    {
        RemoteImpl _remote;

        internal V2RemoteParty( V2RemotePartyConfiguration configuration, V2AppIdentityDomain domain )
            : base( configuration )
        {
            _remote = new RemoteImpl( domain, configuration.Configuration );
        }

        /// <summary>
        /// Gets the configuration object.
        /// </summary>
        public V2RemotePartyConfiguration Configuration => Unsafe.As<V2RemotePartyConfiguration>( _configuration );

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

        public V2AppIdentityDomain Domain => _remote.Domain;

        public bool IsRooted => throw new System.NotImplementedException();

        public Task DestroyAsync() => _remote.DestroyAsync( null );

        public bool SetDestroyed() => _remote.SetDestroyed( null );

        void V2IRemote.DoSetDestroyed( bool isTop ) => _remote.DoSetDestroyed( isTop, null );


    }
}
