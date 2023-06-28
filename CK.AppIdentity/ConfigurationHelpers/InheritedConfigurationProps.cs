using CK.Core;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

namespace CK.AppIdentity
{
    /// <summary>
    /// Currently only handles Allow/DisallowFeatures but should be used for any other
    /// inheritable/combinable properties that may pop.
    /// </summary>
    readonly struct InheritedConfigurationProps
    {
        public readonly IReadOnlySet<string> AllowFeatures;
        public readonly IReadOnlySet<string> DisallowFeatures;
        public readonly bool IsValid => AllowFeatures != null;

        public InheritedConfigurationProps( ApplicationIdentityPartyConfiguration existing )
        {
            AllowFeatures = existing.AllowFeatures;
            DisallowFeatures = existing.DisallowFeatures;
        }

        InheritedConfigurationProps( IReadOnlySet<string> allowFeatures, IReadOnlySet<string> disallowFeatures )
        {
            AllowFeatures = allowFeatures;
            DisallowFeatures = disallowFeatures;
        }

        public static bool TryCreate( IActivityMonitor monitor, ImmutableConfigurationSection root, out InheritedConfigurationProps config )
        {
            if( TryReadAllowDisallowFeatures( monitor, root, out var allow, out var disallow ) )
            {
                config = new InheritedConfigurationProps( allow, disallow );
                return true;
            }
            config = default;
            return false;
        }


        public static bool TryCreate( IActivityMonitor monitor, InheritedConfigurationProps parent, ImmutableConfigurationSection section, out InheritedConfigurationProps config )
        {
            if( TryReadAllowDisallowFeatures( monitor, section, out var allow, out var disallow ) && parent.IsValid )
            {
                allow.AddRange( parent.AllowFeatures.Except( disallow ) );
                disallow.AddRange( parent.DisallowFeatures.Except( allow ) );
                config = new InheritedConfigurationProps(allow, disallow );
                return true;
            }
            config = default;
            return false;
        }

        static bool TryReadAllowDisallowFeatures( IActivityMonitor monitor,
                                                  ImmutableConfigurationSection root,
                                                  [NotNullWhen( true )] out HashSet<string>? allow,
                                                  [NotNullWhen( true )] out HashSet<string>? disallow )
        {
            allow = root.ReadUniqueStringSet( monitor, "AllowFeatures" );
            disallow = root.ReadUniqueStringSet( monitor, "DisallowFeatures" );
            if( allow != null && disallow != null )
            {
                if( !allow.Overlaps( disallow ) )
                {
                    return true;
                }
                monitor.Error( $"The same feature cannot be both in '{root.Path}:AllowFeatures' and 'DisallowFeatures': {allow.Intersect( disallow ).Concatenate()}." );
            }
            return false;
        }

    }
}
