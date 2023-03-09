using CK.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace CK.AppIdentity
{
    /// <summary>
    /// Immutable capture of a <see cref="IConfigurationSection"/>.
    /// </summary>
    public sealed class ImmutableConfigurationSection : IConfigurationSection
    {
        readonly string _key;
        readonly string _path;
        readonly string? _value;
        readonly ImmutableConfigurationSection[] _children;

        /// <summary>
        /// Initializes a new <see cref="ImmutableConfigurationSection"/>.
        /// </summary>
        /// <param name="section">The section to capture.</param>
        public ImmutableConfigurationSection( IConfigurationSection section )
        {
            Debug.Assert( ConfigurationPath.KeyDelimiter == ":" );
            _key = section.Key;
            _path = section.Path;
            _value = section.Value;
            _children = section.GetChildren().Select( c => new ImmutableConfigurationSection( c ) ).ToArray();
        }

        ImmutableConfigurationSection( string path, string key )
        {
            _key = key;
            _path = path;
            _children = Array.Empty<ImmutableConfigurationSection>();
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
            set => Throw.NotSupportedException( $"This configuration '{_path}' is locked." );
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
            set => Throw.NotSupportedException( $"This configuration '{_path}' is locked." );
        }

        IEnumerable<IConfigurationSection> IConfiguration.GetChildren() => _children;

        /// <summary>
        /// Gets the immediate descendant configuration sub-sections: they are also <see cref="ImmutableConfigurationSection"/>.
        /// </summary>
        /// <returns>The configuration sub-sections.</returns>
        public IReadOnlyList<ImmutableConfigurationSection> GetChildren() => _children;

        IConfigurationSection IConfiguration.GetSection( string key ) => GetSection( key );

        /// <inheritdoc cref="IConfiguration.GetSection(string)"/>
        public ImmutableConfigurationSection GetSection( string key )
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
            return new ImmutableConfigurationSection( ConfigurationPath.Combine( _path, key ), errorKey );
        }

        static ImmutableConfigurationSection? Find( ref ReadOnlySpan<char> sKey, ImmutableConfigurationSection[] children )
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

            static ImmutableConfigurationSection? FindCore( ReadOnlySpan<char> sKey, ImmutableConfigurationSection[] children )
            {
                foreach( var child in children )
                {
                    if( sKey.Equals( child.Key, StringComparison.OrdinalIgnoreCase ) ) return child;
                }
                return null;
            }
        }

        /// <summary>
        /// Always returns a never changing token.
        /// </summary>
        /// <returns>A never changing token.</returns>
        public IChangeToken GetReloadToken() => Microsoft.Extensions.FileProviders.NullChangeToken.Singleton;

        /// <summary>
        /// Overridden to display the path and the value or the count of children.
        /// </summary>
        /// <returns>A readable string.</returns>
        public override string ToString() => $"{_path} = {(_value ?? (_children.Length != 0 ? $"{_children.Length} children" : "!Exists"))}";
    }
}
