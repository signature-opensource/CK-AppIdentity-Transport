using CK.Core;
using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    /// <summary>
    /// Context provided to <see cref="ApplicationIdentityFeatureDriver.InitializeAsync(FeatureInitializatonContext)"/>
    /// and to <see cref="ApplicationIdentityFeatureDriver.InitializeDynamicRemoteAsync(FeatureInitializatonContext, IRemoteParty)"/>.
    /// </summary>
    public sealed class FeatureInitializatonContext
    {
        readonly IActivityMonitor _monitor;
        readonly AppIdentityAgent _agent;
        readonly IReadOnlyList<ApplicationIdentityFeatureDriver> _drivers;
        readonly BasicTrampolineRunner _trampoline;

        internal FeatureInitializatonContext( IActivityMonitor monitor, AppIdentityAgent agent, IReadOnlyList<ApplicationIdentityFeatureDriver> drivers )
        {
            _trampoline = new BasicTrampolineRunner();
            _monitor = monitor;
            _agent = agent;
            _drivers = drivers;
        }

        internal async Task<Exception?> ExecuteInitializationAsync()
        {
            foreach( var d in _drivers )
            {
                _trampoline.Trampoline.Add( () => d.InitializeAsync( this ) );
            }
            await _trampoline.ExecuteAllAsync( _monitor );
            if( _trampoline.Result == TrampolineResult.TotalSuccess ) return null;
            return _trampoline.Error ?? new CKException( $"Initialization result is '{_trampoline.Result}'. It is not safe to continue." );
        }

        internal async Task<TrampolineResult> ExecuteDynamicRemoteInitializationAsync( IRemoteParty party )
        {
            foreach( var d in _drivers )
            {
                _trampoline.Trampoline.Add( () => d.InitializeDynamicRemoteAsync( this, party ) );
            }
            await _trampoline.ExecuteAllAsync( _monitor );
            return _trampoline.Result;
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
    }

}
