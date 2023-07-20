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
    /// <para>
    /// This runs in the ApplicationIdentity agent's loop context.
    /// </para>
    /// </summary>
    public sealed class FeatureLifetimeContext
    {
        readonly IActivityMonitor _monitor;
        readonly AppIdentityAgent _agent;
        readonly IReadOnlyList<ApplicationIdentityFeatureDriver> _drivers;
        readonly BasicTrampolineRunner _trampoline;
        IOwnedParty? _targetParty;

        internal FeatureLifetimeContext( IActivityMonitor monitor, AppIdentityAgent agent, IReadOnlyList<ApplicationIdentityFeatureDriver> drivers )
        {
            _trampoline = new BasicTrampolineRunner();
            _monitor = monitor;
            _agent = agent;
            _drivers = drivers;
        }

        /// <summary>
        /// Gets the remotes that are concerned by the current operation, skipping any intermediate <see cref="TenantDomainParty"/>.
        /// <list type="bullet">
        ///   <item>
        ///   For <see cref="ApplicationIdentityFeatureDriver.SetupAsync(FeatureLifetimeContext)"/> and <see cref="ApplicationIdentityFeatureDriver.TeardownAsync(FeatureLifetimeContext)"/>
        ///   these are the <see cref="IApplicationIdentityService.AllRemotes"/>.
        ///   </item>
        ///   <item>
        ///   For <see cref="ApplicationIdentityFeatureDriver.SetupDynamicRemoteAsync(FeatureLifetimeContext, IOwnedParty)"/>) and
        ///   <see cref="ApplicationIdentityFeatureDriver.TeardownDynamicRemoteAsync(FeatureLifetimeContext, IOwnedParty)"/>
        ///   this is the <see cref="IOwnedParty"/> if it is a <see cref="RemoteParty"/>, or its content if it is a <see cref="TenantDomainParty"/>
        ///   (<see cref="ILocalParty.Remotes"/>).
        ///   </item>
        /// </list>
        /// Nothing prevents to associate features to a <see cref="ITenantDomainParty"/> but this is less common: this helper
        /// ease the case where features must be associated to <see cref="IRemoteParty"/>.
        /// </summary>
        /// <returns>The set of remotes to consider for the current operation.</returns>
        public IEnumerable<IRemoteParty> GetAllRemotes()
        {
            return _targetParty switch
            {
                null => _agent.ApplicationIdentityService.AllRemotes,
                TenantDomainParty g => g.Remotes,
                RemoteParty p => new[] { p },
                _ => Throw.NotSupportedException<IEnumerable<IRemoteParty>>()
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

        internal async Task<TrampolineResult> ExecuteSetupDynamicRemoteAsync( IOwnedParty remote )
        {
            _targetParty = remote;
            foreach( var d in _drivers )
            {
                _trampoline.Trampoline.Add( () => d.SetupDynamicRemoteAsync( this, remote ) );
            }
            await _trampoline.ExecuteAllAsync( _monitor );
            return _trampoline.Result;
        }

        internal Task ExecuteTeardownDynamicRemoteAsync( IOwnedParty party )
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
