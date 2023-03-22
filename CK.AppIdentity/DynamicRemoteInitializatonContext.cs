using CK.Core;

namespace CK.AppIdentity
{
    /// <summary>
    /// This context is provided to <see cref="ApplicationIdentityFeatureDriver.InitializeDynamicRemoteAsync(DynamicRemoteInitializatonContext)"/>.
    /// This context is a <see cref="TrampolineRunner{TSelf}"/> and provides a monitor, a shared memory that can used to share
    /// initialization states, a <see cref="TrampolineRunner{TSelf}.Trampoline"/> to handle deferred initializations,  the
    /// <see cref="ApplicationIdentityService"/>'s <see cref="Agent"/> and the <see cref="RemoteParty"/> to initialize.
    /// </summary>
    public sealed class DynamicRemoteInitializatonContext : TrampolineRunner<DynamicRemoteInitializatonContext>
    {
        readonly AppIdentityAgent _agent;
        readonly IRemoteParty _remoteParty;

        internal DynamicRemoteInitializatonContext( IActivityMonitor monitor, AppIdentityAgent agent, IRemoteParty remoteParty )
            : base( monitor )
        {
            _agent = agent;
            _remoteParty = remoteParty;
        }

        /// <summary>
        /// Gets the <see cref="AppIdentityAgent"/>.
        /// </summary>
        public AppIdentityAgent Agent => _agent;

        /// <summary>
        /// Gets the dynamic remote party that must be initialized.
        /// </summary>
        public IRemoteParty RemoteParty => _remoteParty;
    }


}
