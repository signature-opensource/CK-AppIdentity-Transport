using CK.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    /// <summary>
    /// </summary>
    public sealed class V2ApplicationIdentityService : V2AppIdentityDomain
    {
        readonly AppIdentityAgent _agent;
        internal readonly List<ApplicationIdentityFeatureDriver> _builders;
        internal TaskCompletionSource _initialization;

        internal V2ApplicationIdentityService( V2ApplicationIdentityConfiguration configuration, IServiceProvider serviceProvider )
            : base( configuration, null )
        {
            _builders = new List<ApplicationIdentityFeatureDriver>();
            _initialization = new TaskCompletionSource();
            _agent = new AppIdentityAgent( null/*this*/, serviceProvider );
        }

        internal AppIdentityAgent Agent => _agent;

        /// <summary>
        /// Gets the configuration object.
        /// </summary>
        public new V2ApplicationIdentityConfiguration Configuration => Unsafe.As<V2ApplicationIdentityConfiguration>( _configuration );

        /// <summary>
        /// Gets the this application party name.
        /// </summary>
        public string PartyName => Configuration.PartyName;

    }
}
