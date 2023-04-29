using CK.Core;
using CK.PerfectEvent;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.Tests
{
    public sealed class ApplicationIdentityWithServices : IApplicationIdentity, IAsyncDisposable
    {
        readonly ApplicationIdentityService _s;
        readonly ServiceProvider _serviceProvider;

        public ApplicationIdentityWithServices( ApplicationIdentityService s, ServiceProvider serviceProvider )
        {
            _s = s;
            _serviceProvider = serviceProvider;
        }

        public ApplicationIdentityService ApplicationIdentityService => ((IApplicationIdentity)_s).ApplicationIdentityService;

        public IServiceProvider ServiceProvider => _serviceProvider;

        public ApplicationIdentityConfiguration Configuration => _s.Configuration;

        public string DomainName => _s.DomainName;

        public string EnvironmentName => _s.EnvironmentName;

        public ILocalParty Local => _s.Local;

        public IReadOnlyCollection<IRemoteParty> Remotes => _s.Remotes;

        public PerfectEvent<IRemoteParty> RemotesChanged => _s.RemotesChanged;

        public Task<IRemoteParty?> AddDynamicRemoteAsync( IActivityMonitor monitor, Action<MutableConfigurationSection> configuration )
        {
            return _s.AddDynamicRemoteAsync( monitor, configuration );
        }

        public async ValueTask DisposeAsync()
        {
            await _s.DisposeAsync();
            await _serviceProvider.DisposeAsync();
        }
    }
}
