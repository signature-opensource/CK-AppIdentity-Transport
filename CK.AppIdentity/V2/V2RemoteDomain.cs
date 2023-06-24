using System;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    public sealed class V2RemoteDomain : V2AppIdentityDomain, V2IRemote
    {
        RemoteImpl _remote;

        internal V2RemoteDomain( V2DomainConfiguration configuration, V2AppIdentityDomain domain )
            : base( configuration, domain.ApplicationIdentityService )
        {
            _remote = new RemoteImpl( domain, configuration.Configuration );
        }

        public V2AppIdentityDomain Domain => _remote.Domain;

        public bool IsDynamic => _remote.IsDynamic;

        public bool IsDestroyed => _remote.IsDestroyed;

        public Task DestroyAsync() => _remote.DestroyAsync( this );

        public bool SetDestroyed() => _remote.SetDestroyed( this );

        void V2IRemote.DoSetDestroyed( bool isTop ) => _remote.DoSetDestroyed( isTop, this );
    }
}
