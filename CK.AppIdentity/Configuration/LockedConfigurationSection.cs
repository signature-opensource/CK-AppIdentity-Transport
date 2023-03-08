using CK.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    /// <summary>
    /// Immutable capture of a <see cref="IConfigurationSection"/>.
    /// </summary>
    public sealed class LockedConfigurationSection : IConfigurationSection
    {
        readonly string _key;
        readonly string _path;
        readonly string? _value;
        readonly LockedConfigurationSection[] _children;

        /// <summary>
        /// Initializes a new <see cref="LockedConfigurationSection"/>.
        /// </summary>
        /// <param name="section">The section to capture.</param>
        public LockedConfigurationSection( IConfigurationSection section )
        {
            _key = section.Key;
            _path = section.Path;
            _value = section.Value;
            _children = section.GetChildren().Select( c => new LockedConfigurationSection( c ) ).ToArray();
        }

        LockedConfigurationSection( string path, string key )
        {
            _key = key;
            _path = path;
            _children = Array.Empty<LockedConfigurationSection>();
        }

        /// <summary>
        /// Gets a configuration value. Setting it throws a <see cref="NotSupportedException"/>. 
        /// </summary>
        /// <param name="key">The configuration key to find.</param>
        /// <returns>The value or null if not found.</returns>
        public string? this[string key]
        {
            get
            {
                var sKey = key.AsSpan();
                return Find( ref sKey, _children )?.Value;
            }

            set => Throw.NotSupportedException( "This configuration is locked." );
        }

        /// <inheritdoc />
        public string Key => _key;

        /// <inheritdoc />
        public string Path => _path;

        /// <summary>
        /// Gets the section value. Setting it throws a <see cref="NotSupportedException"/>. 
        /// </summary>
        public string? Value
        {
            get => _value;
            set => Throw.NotSupportedException( "This configuration is locked." );
        }

        IEnumerable<IConfigurationSection> IConfiguration.GetChildren() => _children;

        /// <summary>
        /// Gets the immediate descendant configuration sub-sections: they are also <see cref="LockedConfigurationSection"/>.
        /// </summary>
        /// <returns>The configuration sub-sections.</returns>
        public IReadOnlyList<LockedConfigurationSection> GetChildren() => _children;

        IConfigurationSection IConfiguration.GetSection( string key ) => GetSection( key );

        /// <inheritdoc cref="IConfiguration.GetSection(string)"/>
        public LockedConfigurationSection GetSection( string key )
        {
            var sKey = key.AsSpan();
            var s = Find( ref sKey, _children );
            if( s != null ) return s;
            // This mimics the key returned by the standard .Net implementation.
            var errorKey = key;
            if( sKey.Length != errorKey.Length )
            {
                var sErrorKey = sKey.Trim( ':' );
                if( sErrorKey.Contains(':' ) )
                {
                    errorKey = string.Empty;
                }
                else
                {
                    errorKey = sErrorKey.ToString();
                }
            }
            return new LockedConfigurationSection( ConfigurationPath.Combine( _path, key ), errorKey );
        }

        static LockedConfigurationSection? Find( ref ReadOnlySpan<char> sKey, LockedConfigurationSection[] children )
        {
            for( ; ; )
            {
                var idx = sKey.IndexOf( ':' );
                if( idx < 0 ) return FindCore( sKey, children );
                var sub = FindCore( sKey.Slice( 0, idx ), children );
                sKey = sKey.Slice( idx + 1 );
                if( sub == null ) return null;
                children = sub._children;
            }

            static LockedConfigurationSection? FindCore( ReadOnlySpan<char> sKey, LockedConfigurationSection[] children )
            {
                foreach( var child in children )
                {
                    if( sKey.Equals( child.Key, StringComparison.OrdinalIgnoreCase ) ) return child;
                }
                return null;
            }
        }

        public IChangeToken GetReloadToken() => Microsoft.Extensions.FileProviders.NullChangeToken.Singleton;

    }
}
