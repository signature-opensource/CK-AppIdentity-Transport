using CK.Core;

namespace CK.AppIdentity
{
    /// <summary>
    /// This context is provided to <see cref="ApplicationIdentityFeatureDriver.InitializeAsync(FeatureInitializatonContext)"/>.
    /// This context is a <see cref="TrampolineRunner{TSelf}"/> and provides a monitor, a shared memory that can used to share
    /// initialization states, a <see cref="TrampolineRunner{TSelf}.Trampoline"/> to handle deferred initializations and
    /// the <see cref="ApplicationIdentityService"/>'s <see cref="Agent"/>.
    /// </summary>
    public sealed class FeatureInitializatonContext : TrampolineRunner<FeatureInitializatonContext>
    {
        readonly AppIdentityAgent _agent;

        internal FeatureInitializatonContext( IActivityMonitor monitor, AppIdentityAgent agent )
            : base( monitor )
        {
            _agent = agent;
        }

        /// <summary>
        /// Gets the <see cref="AppIdentityAgent"/>.
        /// </summary>
        public AppIdentityAgent Agent => _agent;
    }


}
