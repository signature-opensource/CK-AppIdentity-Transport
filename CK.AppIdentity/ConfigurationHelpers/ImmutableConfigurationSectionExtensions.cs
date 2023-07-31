using CK.Core;
using System.Collections.Generic;
using System.Linq;
using System;
using System.Diagnostics;

namespace CK.AppIdentity
{
    public static class ImmutableConfigurationSectionExtensions
    {
        /// <summary>
        /// Emits an error if the configuration key exists and returns false.
        /// </summary>
        /// <param name="s">This section.</param>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="key">The configuration key.</param>
        /// <param name="reasonPhrase">The reason why this property must not be defined here.</param>
        /// <returns>True on success (no configuration), false if the key exists..</returns>
        public static bool CheckNotExist( this ImmutableConfigurationSection s, IActivityMonitor monitor, string key, string reasonPhrase )
        {
            if( s.TryGetSection( key ) != null )
            {
                monitor.Error( $"Invalid '{s.Path}:{key}' key: {reasonPhrase}" );
                return false;
            }
            return true;
        }

        /// <summary>
        /// Lookups a "true"/"false" (case insensitive) boolean value in this section or above.
        /// Defaults to false.
        /// </summary>
        /// <param name="s">This section.</param>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="key">The configuration key.</param>
        /// <returns>The boolean value, false by default.</returns>
        public static bool LookupBooleanValue( this ImmutableConfigurationSection s, IActivityMonitor monitor, string key )
        {
            var a = s.TryLookupValue( key );
            if( !bool.TryParse( a, out var value ) && a != null )
            {
                Throw.DebugAssert( !value );
                monitor.Warn( $"Unable to parse '{s.Path}:{key}' value, expected 'true' or 'false' but got '{a}'. Using default false." );
            }
            return value;
        }

        /// <summary>
        /// Helper that reads a string array from a string value, a comma separated string, or children
        /// sections (with string value or comma separated string) that must have integer keys ("0", "1",...).
        /// Returns null on error (and the error is logged).
        /// </summary>
        /// <param name="s">This section.</param>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="key">The configuration key.</param>
        /// <returns>The string array (empty if the key doesn't exist) or null on error.</returns>
        public static string[]? ReadStringArray( ImmutableConfigurationSection s, IActivityMonitor monitor, string key )
        {
            return s.TryGetSection( key ).ReadStringArray( monitor );
        }

        /// <summary>
        /// Helper that reads a string array from a string value, a comma separated string, or children
        /// sections (with string value or comma separated string) that must have integer keys ("0", "1",...).
        /// Returns null on error (and the error is logged).
        /// </summary>
        /// <param name="s">This section.</param>
        /// <param name="monitor">The monitor to use.</param>
        /// <returns>The string array (empty if the section is null) or null on error.</returns>
        public static string[]? ReadStringArray( this ImmutableConfigurationSection? s, IActivityMonitor monitor )
        {
            if( s != null )
            {
                if( s.Value != null )
                {
                    return s.Value.Split( ',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.RemoveEmptyEntries );
                }
                var result = new List<string>();
                foreach( var o in s.GetChildren() )
                {
                    var value = o.Value;
                    if( value == null || !int.TryParse( o.Key, out _ ) )
                    {
                        monitor.Error( $"Invalid array configuration for '{s.Path}': key '{o.Path}' is invalid." );
                        return null;
                    }
                    if( string.IsNullOrEmpty( value ) ) continue;
                    if( value.Contains( ',' ) ) result.AddRangeArray( value.Split( ',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.RemoveEmptyEntries ) );
                    else
                    {
                        value = value.Trim();
                        if( value.Length > 0 ) result.Add( value );
                    }
                }
                return result.ToArray();
            }
            return Array.Empty<string>();
        }

        /// <summary>
        /// Calls <see cref="ReadStringArray(ImmutableConfigurationSection, IActivityMonitor)"/> and ensures that
        /// strings are unique.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="s">The section.</param>
        /// <param name="comparer">Optional comparer.</param>
        /// <returns>A set of unique strings or null on error.</returns>
        public static HashSet<string>? ReadUniqueStringSet( this ImmutableConfigurationSection? s, IActivityMonitor monitor, StringComparer? comparer = null )
        {
            var a = ReadStringArray( s, monitor );
            if( a == null ) return null;
            var set = new HashSet<string>( a, comparer );
            if( set.Count != a.Length )
            {
                Throw.DebugAssert( s != null, "Since we found something." );
                monitor.Error( $"Duplicate found in '{s.Path}': {a.Except( set ).Concatenate()}." );
                return null;
            }
            return set;
        }

        /// <summary>
        /// Calls <see cref="ReadStringArray(ImmutableConfigurationSection, IActivityMonitor, string)"/> and ensures that
        /// strings are unique.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="s">The section.</param>
        /// <param name="key">The configuration key.</param>
        /// <param name="comparer">Optional comparer.</param>
        /// <returns>A set of unique strings or null on error.</returns>
        public static HashSet<string>? ReadUniqueStringSet( this ImmutableConfigurationSection s, IActivityMonitor monitor, string key, StringComparer? comparer = null )
        {
            return s.TryGetSection( key ).ReadUniqueStringSet( monitor, comparer );
        }
    }
}
