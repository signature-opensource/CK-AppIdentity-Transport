using CK.Core;
using System;
using System.Collections.Generic;

namespace CK.AppIdentity
{
    /// <summary>
    /// Remote party can be <see cref="IsDynamic"/> or bound to a <see cref="Configuration"/>.
    /// </summary>
    public sealed class RemoteParty
    {
        object[] _features;
        readonly AppIdentityService _appIdentity;
        readonly RemotePartyConfiguration? _configuration;
        readonly string _name;
        readonly Uri? _uri;
        readonly string _domainName;
        readonly string _environmentName;

        internal RemoteParty( AppIdentityService appIdentity, RemotePartyConfiguration configuration  )
        {
            _features = Array.Empty<object>();
            _appIdentity = appIdentity;
            _configuration = configuration;
            _name = configuration.Name;
            _uri = configuration.Uri;
            _domainName = configuration.DomainName;
            _environmentName = configuration.EnvironmentName;
        }

        /// <summary>
        /// Gets the application identity service.
        /// </summary>
        public AppIdentityService AppIdentityService => _appIdentity;

        /// <summary>
        /// Gets whether this is a dynamic remote party.
        /// </summary>
        public bool IsDynamic => _configuration == null;

        /// <summary>
        /// Gets the required name of this party that must be an identifier: it must only contain 'A'-'Z', 'a'-'z', '0'-'9' and '_' characters
        /// and must not start with a digit nor a '_'.
        /// </summary>
        public string Name => _name;

        /// <summary>
        /// Gets the uri of this party.
        /// This is null if this remote is only a client of this local application.
        /// </summary>
        public Uri? Uri => _uri;

        /// <summary>
        /// Gets the domain name of this party.
        /// </summary>
        public string DomainName => _domainName;

        /// <summary>
        /// Gets the environment name of this party.
        /// </summary>
        public string EnvironmentName => _environmentName;

        /// <summary>
        /// Gets the features associated to this <see cref="RemoteParty"/>.
        /// </summary>
        public IEnumerable<object> Features => _features;

        /// <summary>
        /// Atomically (thread safe) adds a feature if it doesn't already exist.
        /// </summary>
        /// <param name="feature">The feature to add.</param>
        /// <returns>True if the feature has been added, false if the feature already exists.</returns>
        public bool AddFeature( object feature )
        {
            var features = Util.InterlockedAddUnique( ref _features, feature );
            return Array.IndexOf( features, feature ) >= 0;
        }

        /// <summary>
        /// Gets the configuration if this is a configured party.
        /// </summary>
        public RemotePartyConfiguration? Configuration => _configuration;

    }
}
