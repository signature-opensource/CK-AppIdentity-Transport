using CK.Core;
using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    /// <summary>
    /// Context provided to <see cref="ApplicationIdentityFeatureDriver.SetupAsync(FeatureLifetimeContext)"/>
    /// and to <see cref="ApplicationIdentityFeatureDriver.SetupDynamicRemoteAsync(FeatureLifetimeContext, IRemoteParty)"/>.
    /// </summary>
    public sealed class FeatureLifetimeContext
    {
        readonly IActivityMonitor _monitor;
        readonly AppIdentityAgent _agent;
        readonly IReadOnlyList<ApplicationIdentityFeatureDriver> _drivers;
        readonly BasicTrampolineRunner _trampoline;
        IRemote? _targetParty;

        internal FeatureLifetimeContext( IActivityMonitor monitor, AppIdentityAgent agent, IReadOnlyList<ApplicationIdentityFeatureDriver> drivers )
        {
            _trampoline = new BasicTrampolineRunner();
            _monitor = monitor;
            _agent = agent;
            _drivers = drivers;
        }

        /// <summary>
        /// Gets the remotes that are concerned by the current operation, skipping any intermediate <see cref="RemoteGroup"/>.
        /// <list type="bullet">
        ///   <item>
        ///   For <see cref="ApplicationIdentityFeatureDriver.SetupAsync(FeatureLifetimeContext)"/> and <see cref="ApplicationIdentityFeatureDriver.TeardownAsync(FeatureLifetimeContext)"/>
        ///   these are all <see cref="RemoteParty"/> and <see cref="RemoteExternal"/> of the application (depth-first traversal).
        ///   </item>
        ///   <item>
        ///   For <see cref="ApplicationIdentityFeatureDriver.SetupDynamicRemoteAsync(FeatureLifetimeContext, IRemote)"/>) and
        ///   <see cref="ApplicationIdentityFeatureDriver.TeardownDynamicRemoteAsync(FeatureLifetimeContext, IRemote)"/>
        ///   this can be the <see cref="IRemote"/> if it is a <see cref="RemoteParty"/> or <see cref="RemoteExternal"/>,
        ///   or its content if it is a <see cref="RemoteGroup"/> (this uses <see cref="IRemoteOwner.AllRemotes"/>).
        ///   </item>
        /// </list>
        /// Nothing prevents to associate features to a <see cref="RemoteGroup"/> but this should be quite rare: this helper
        /// ease the common case where features must be associated to <see cref="RemoteParty"/> or <see cref="RemoteExternal"/>.
        /// </summary>
        /// <returns>The set of leaf remotes for the current operation.</returns>
        public IEnumerable<IRemote> GetAllLeafRemotes()
        {
            return _targetParty switch
            {
                null => _agent.ApplicationIdentityService.AllRemotes,
                RemoteGroup g => g.AllRemotes,
                _ => new[] { _targetParty }
            };
        }

        /// <summary>
        /// Gets the <see cref="ApplicationIdentityService"/>'s agent.
        /// </summary>
        public AppIdentityAgent Agent => _agent;

        /// <summary>
        /// Gets the monitor to use.
        /// </summary>
        public IActivityMonitor Monitor => _monitor;

        /// <summary>
        /// Gets a trampoline that must be used to defer actions.
        /// </summary>
        public BasicTrampoline Trampoline => _trampoline.Trampoline;

        /// <summary>
        /// Gets an optional memory that can be used to share state between actions.
        /// </summary>
        public IDictionary<object, object> Memory => _trampoline.Memory;

        internal async Task<Exception?> ExecuteSetupAsync()
        {
            _targetParty = null;
            foreach( var d in _drivers )
            {
                _trampoline.Trampoline.Add( () => d.SetupAsync( this ) );
            }
            await _trampoline.ExecuteAllAsync( _monitor );
            if( _trampoline.Result == TrampolineResult.TotalSuccess ) return null;
            return _trampoline.Error ?? new CKException( $"Initialization result is '{_trampoline.Result}'. It is not safe to continue." );
        }

        internal async Task<TrampolineResult> ExecuteSetupDynamicRemoteAsync( IRemote remote )
        {
            _targetParty = remote;
            foreach( var d in _drivers )
            {
                _trampoline.Trampoline.Add( () => d.SetupDynamicRemoteAsync( this, remote ) );
            }
            await _trampoline.ExecuteAllAsync( _monitor );
            return _trampoline.Result;
        }

        internal Task ExecuteTeardownDynamicRemoteAsync( IRemote party )
        {
            _targetParty = party;
            // Calls the drivers in reverse order for the destruction.
            foreach( var d in _drivers.Reverse() )
            {
                _trampoline.Trampoline.Add( () => d.TeardownDynamicRemoteAsync( this, party ) );
            }
            return _trampoline.ExecuteAllAsync( _monitor );
        }

        internal Task ExecuteTeardownAsync()
        {
            _targetParty = null;
            // Calls the drivers in reverse order for the destruction.
            foreach( var d in _drivers.Reverse() )
            {
                _trampoline.Trampoline.Add( () => d.TeardownAsync( this ) );
            }
            return _trampoline.ExecuteAllAsync( _monitor );
        }

    }

}
