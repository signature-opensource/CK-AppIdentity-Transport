using CK.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace CK.AppIdentity
{
    /// <summary>
    /// Mutable <see cref="IConfigurationSection"/>: this acts as a simple configuration builder
    /// that can then be captured by a <see cref="ImmutableConfigurationSection"/>.
    /// </summary>
    public sealed class MutableConfigurationSection : IConfigurationSection
    {
        readonly string _key;
        readonly string _path;
        string? _value;
        readonly List<MutableConfigurationSection> _children;

        /// <summary>
        /// Initializes a new <see cref="ImmutableConfigurationSection"/>.
        /// </summary>
        /// <param name="section">The section to capture.</param>
        public MutableConfigurationSection( IConfigurationSection section )
        {
            Throw.CheckNotNullArgument( section );
            Debug.Assert( ConfigurationPath.KeyDelimiter == ":" );
            _key = section.Key;
            _path = section.Path;
            _value = section.Value;
            _children = section.GetChildren().Select( c => new MutableConfigurationSection( c ) ).ToList();
        }

        /// <summary>
        /// Initializes a new <see cref="MutableConfigurationSection"/> on a root path.
        /// </summary>
        /// <param name="path">The root path. It must be a valid path.</param>
        public MutableConfigurationSection( string path )
        {
            CheckKeyArgument( path, path, nameof( path ) );
            _key = ConfigurationPath.GetSectionKey( path );
            _path = path;
            _children = new List<MutableConfigurationSection>();
        }


        MutableConfigurationSection( string parentPath, string key )
        {
            _key = key;
            _path = parentPath + ':' + key;
            _children = new List<MutableConfigurationSection>();
        }

        /// <summary>
        /// Gets a configuration value.
        /// Setting a value (even null) on a section clears any existing subordinated children. 
        /// </summary>
        /// <param name="key">The configuration key to find.</param>
        /// <returns>The value or null if not found.</returns>
        public string? this[string key]
        {
            get
            {
                var sKey = key.AsSpan();
                var parent = this;
                return Find( ref sKey, ref parent )?.Value;
            }
            set => GetMutableSection( key ).Value = value;
        }

        /// <inheritdoc />
        public string Key => _key;

        /// <inheritdoc />
        public string Path => _path;

        /// <summary>
        /// Gets the section value. Setting it clears the <see cref="GetChildren()"/> collection.
        /// Setting a null value makes this section empty: <see cref="ConfigurationExtensions.Exists(IConfigurationSection)"/>
        /// becomes false.
        /// </summary>
        public string? Value
        {
            get => _value;
            set
            {
                if( _value != value )
                {
                    _children.Clear();
                    _value = value;
                }
            }
        }

        IEnumerable<IConfigurationSection> IConfiguration.GetChildren() => _children.Where( c => c.Exists() );

        /// <summary>
        /// Gets the immediate descendant <see cref="MutableConfigurationSection"/> sub-sections: they can
        /// be empty and have no value (<see cref="ConfigurationExtensions.Exists(IConfigurationSection)"/> can be false).
        /// </summary>
        /// <returns>The configuration sub-sections.</returns>
        public IReadOnlyList<MutableConfigurationSection> GetMutableChildren() => _children;

        IConfigurationSection IConfiguration.GetSection( string key ) => GetMutableSection( key );

        /// <summary>
        /// Finds or creates an existing subordinated section. The key can contain ":" delimiters: sub sections
        /// are found or created accordingly.
        /// <para>
        /// If the section is created, it has no value (<see cref="Value"/> is null) and no children
        /// (<see cref="ConfigurationExtensions.Exists(IConfigurationSection)"/> is false).
        /// </para>
        /// </summary>
        /// <param name="key">The section key relative to this <see cref="Path"/>.</param>
        /// <returns>The mutable section.</returns>
        public MutableConfigurationSection GetMutableSection( string key )
        {
            var sKey = key.AsSpan();
            var parent = this;
            var s = Find( ref sKey, ref parent );
            if( s != null ) return s;
            // Here, instead of reproducing the standard .Net implementation behavior,
            // we check the key syntax and ensure the path to target.
            CheckKeyArgument( key, sKey, nameof( key ) );
            int idx;
            if( (idx = sKey.IndexOf( ':' )) != -1 )
            {
                do
                {
                    key = sKey.Slice( 0, idx ).ToString();
                    s = new MutableConfigurationSection( parent._path, key );
                    parent._children.Add( s );
                    sKey = sKey.Slice( idx + 1 );
                    parent = s;
                }
                while( (idx = sKey.IndexOf( ':' )) != -1 );
                key = sKey.ToString();
            }
            s = new MutableConfigurationSection( parent._path, key );
            parent._children.Add( s );
            return s;
        }

        static void CheckKeyArgument( string key, ReadOnlySpan<char> sKey, string parameterName )
        {
            if( !IsValidKey( sKey ) )
            {
                if( key == null ) Throw.ArgumentNullException( parameterName );
                Throw.ArgumentException( $"Configuration key '{key}': invalid {parameterName}." );
            }
        }

        static bool IsValidKey( ReadOnlySpan<char> sKey )
        {
            return sKey.Length > 0
                   && !sKey.Contains( "::".AsSpan(), StringComparison.Ordinal )
                   && sKey[0] != ':'
                   && sKey[sKey.Length - 1] != ':';
        }

        /// <summary>
        /// Adds a set of configuration values to this configuration.
        /// </summary>
        /// <param name="values"></param>
        public void Add( IEnumerable<KeyValuePair<string, string>> values )
        {
            foreach( var kv in values)
            {
                GetMutableSection( kv.Key ).Value = kv.Value;
            }
        }

        static MutableConfigurationSection? Find( ref ReadOnlySpan<char> sKey, ref MutableConfigurationSection parent )
        {
            for(; ; )
            {
                var idx = sKey.IndexOf( ':' );
                if( idx < 0 ) return FindCore( sKey, parent._children );
                var sub = FindCore( sKey.Slice( 0, idx ), parent._children );
                if( sub == null ) return null;
                sKey = sKey.Slice( idx + 1 );
                parent = sub;
            }

            static MutableConfigurationSection? FindCore( ReadOnlySpan<char> sKey, List<MutableConfigurationSection> children )
            {
                foreach( var child in children )
                {
                    if( sKey.Equals( child.Key, StringComparison.OrdinalIgnoreCase ) ) return child;
                }
                return null;
            }
        }

        public IChangeToken GetReloadToken() => Microsoft.Extensions.FileProviders.NullChangeToken.Singleton;

        public override string ToString() => $"{_path} = {(_value ?? (_children.Count != 0 ? $"{_children.Count} children" : "!Exists"))}";

    }
}
