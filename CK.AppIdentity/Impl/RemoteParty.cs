using CK.Core;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    sealed class RemoteParty : IRemoteParty
    {
        object[] _features;
        readonly IApplicationIdentity _appIdentity;
        readonly RemotePartyConfiguration _configuration;
        readonly NormalizedPath _fullName;
        readonly DomainApplicationIdentity? _domainAppIdentityService;
        readonly bool _isDynamic;
        int _isDestroyed;
        internal TaskCompletionSource? _destroyTCS;

        internal RemoteParty( IApplicationIdentity appIdentity, RemotePartyConfiguration configuration )
        {
            _features = Array.Empty<object>();
            _appIdentity = appIdentity;
            _configuration = configuration;
            _domainAppIdentityService = configuration.DomainConfiguration != null
                                        ? new DomainApplicationIdentity( this )
                                        : null;
            _fullName = LocalParty.BuildFullName( configuration.DomainName, configuration.EnvironmentName, configuration.Name );
            _isDynamic = ReferenceEquals( configuration.Configuration.Key, "Dynamic" );
        }

        /// <inheritdoc />
        public IApplicationIdentity ApplicationIdentity => _appIdentity;

        /// <inheritdoc />
        public bool IsRooted => _appIdentity is ApplicationIdentityService;

        /// <inheritdoc />
        public bool IsDynamic => _isDynamic;

        /// <inheritdoc />
        public string Name => _configuration.Name;

        /// <inheritdoc />
        public NormalizedPath FullName => _fullName;

        /// <inheritdoc />
        public string? Address => _configuration.Address;

        /// <inheritdoc />
        public string DomainName => _configuration.DomainName;

        /// <inheritdoc />
        public string EnvironmentName => _configuration.EnvironmentName;

        /// <inheritdoc />
        public IEnumerable<object> Features => _features;

        /// <inheritdoc />
        public void AddFeature( object feature )
        {
            Util.InterlockedAddUnique( ref _features, feature );
        }

        /// <inheritdoc />
        public RemotePartyConfiguration Configuration => _configuration;

        /// <inheritdoc />
        public IDomainApplicationIdentity? DomainApplicationIdentity => _domainAppIdentityService;

        /// <inheritdoc />
        public bool IsDestroyed => _isDestroyed != 0;

        /// <inheritdoc />
        public bool SetDestroyed()
        {
            Throw.CheckState( IsDynamic );
            return DoSetDestroyed( true );
        }

        bool DoSetDestroyed( bool isTop )
        {
            if( Interlocked.CompareExchange( ref _isDestroyed, 1, 0 ) == 0 )
            {
                _destroyTCS = new TaskCompletionSource();
                // We set the destroy flag and tcs on subordinates but we
                // trigger the agent on the destroyed root so that the feature drivers
                // see the "destruction" the same as the "initialization".
                if( _domainAppIdentityService != null )
                {
                    // Immediately condemns the child remotes and ask to handle
                    // their destruction first.
                    // They know that their host is destroyed (we set the flag to enter this).
                    _domainAppIdentityService._local._isDestroyed = true;
                    foreach( var r in _domainAppIdentityService._remotes )
                    {
                        // Use the CAS check on destroy to prevent any
                        // duplicate request but skip the IsDynamic check.
                        r.DoSetDestroyed( false );
                    }
                }
                if( isTop ) _appIdentity.ApplicationIdentityService.Agent.OnDestroy( this );
                return true;
            }
            return false;
        }

        /// <inheritdoc />
        public Task DestroyAsync()
        {
            SetDestroyed();
            Debug.Assert( _destroyTCS != null );
            return _destroyTCS.Task;
        }

        public override string ToString() => _fullName.Path;
    }
}
