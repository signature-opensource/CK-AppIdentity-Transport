using CK.Core;
using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
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

        internal FeatureLifetimeContext( IActivityMonitor monitor, AppIdentityAgent agent, IReadOnlyList<ApplicationIdentityFeatureDriver> drivers )
        {
            _trampoline = new BasicTrampolineRunner();
            _monitor = monitor;
            _agent = agent;
            _drivers = drivers;
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
            foreach( var d in _drivers )
            {
                _trampoline.Trampoline.Add( () => d.SetupAsync( this ) );
            }
            await _trampoline.ExecuteAllAsync( _monitor );
            if( _trampoline.Result == TrampolineResult.TotalSuccess ) return null;
            return _trampoline.Error ?? new CKException( $"Initialization result is '{_trampoline.Result}'. It is not safe to continue." );
        }

        internal async Task<TrampolineResult> ExecuteSetupDynamicRemoteAsync( IRemoteParty party )
        {
            foreach( var d in _drivers )
            {
                _trampoline.Trampoline.Add( () => d.SetupDynamicRemoteAsync( this, party ) );
            }
            await _trampoline.ExecuteAllAsync( _monitor );
            return _trampoline.Result;
        }

        internal Task ExecuteTeardownDynamicRemoteAsync( IRemoteParty party )
        {
            // Calls the drivers in reverse order for the destruction.
            foreach( var d in _drivers.Reverse() )
            {
                _trampoline.Trampoline.Add( () => d.TeardownDynamicRemoteAsync( this, party ) );
            }
            return _trampoline.ExecuteAllAsync( _monitor );
        }

        internal Task ExecuteTeardownAsync()
        {
            // Calls the drivers in reverse order for the destruction.
            foreach( var d in _drivers.Reverse() )
            {
                _trampoline.Trampoline.Add( () => d.TeardownAsync( this ) );
            }
            return _trampoline.ExecuteAllAsync( _monitor );
        }

    }

}
