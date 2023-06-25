using System;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    public sealed class RemoteDomain : ApplicationIdentityDomain, IRemote
    {
        RemoteImpl _remote;

        internal RemoteDomain( DomainConfiguration configuration, ApplicationIdentityDomain domain )
            : base( configuration, domain.ApplicationIdentityService )
        {
            _remote = new RemoteImpl( domain, configuration.Configuration );
        }

        public ApplicationIdentityDomain Domain => _remote.Domain;

        public bool IsDynamic => _remote.IsDynamic;

        public bool IsDestroyed => _remote.IsDestroyed;

        public Task DestroyAsync() => _remote.DestroyAsync( this );

        public bool SetDestroyed() => _remote.SetDestroyed( this );

        void IRemote.DoSetDestroyed( bool isTop ) => _remote.DoSetDestroyed( isTop, this );
    }
}
