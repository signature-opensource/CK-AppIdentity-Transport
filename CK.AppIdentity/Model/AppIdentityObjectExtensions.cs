using CK.Core;
using System;
using System.Collections.Generic;
using System.Linq;

namespace CK.AppIdentity
{
    public static class AppIdentityObjectExtensions
    {
        /// <summary>
        /// Gets the first object feature that is a <typeparamref name="T"/> or null if not found.
        /// </summary>
        /// <typeparam name="T">The feature type.</typeparam>
        /// <param name="p">This party.</param>
        /// <returns>The feature or null.</returns>
        public static T? GetFeature<T>( this IAppIdentityObject p ) => p.Features.OfType<T>().FirstOrDefault();

        /// <summary>
        /// Gets the first object feature that is a <typeparamref name="T"/> or throws
        /// an <see cref="InvalidOperationException"/>
        /// </summary>
        /// <typeparam name="T">The feature type.</typeparam>
        /// <param name="p">This party.</param>
        /// <returns>The feature.</returns>
        public static T GetRequiredFeature<T>( this IAppIdentityObject p )
        {
            var feature = p.Features.OfType<T>().FirstOrDefault();
            if( feature == null ) Throw.InvalidOperationException( $"Unable to find a feature '{typeof(T).ToCSharpName()}' in '{p}'." );
            return feature;
        }

        /// <summary>
        /// Gets the party from its name or null if not found.
        /// </summary>
        /// <param name="c">This collection.</param>
        /// <param name="name">The <see cref="IRemoteParty.Name"/> to find.</param>
        /// <returns>The party or null.</returns>
        public static IRemoteParty? Find( this IReadOnlyCollection<IRemoteParty> c, string name ) => c.FirstOrDefault( p => p.Name == name );

        /// <summary>
        /// Gets the party from its name or throws an <see cref="InvalidOperationException"/>.
        /// </summary>
        /// <param name="c">This collection.</param>
        /// <param name="name">The <see cref="IRemoteParty.Name"/> to find.</param>
        /// <returns>The party or null.</returns>
        public static IRemoteParty FindRequired( this IReadOnlyCollection<IRemoteParty> c, string name )
        {
            var p = c.FirstOrDefault( p => p.Name == name );
            if( p == null ) Throw.InvalidOperationException( $"Unable to find remote named '{name}'." );
            return p;
        }

        /// <summary>
        /// Gets all the remotes of this service recursively across remotes that define a domain.
        /// Remotes that define a domain don't appear in this list.
        /// </summary>
        /// <param name="s">This identity service.</param>
        /// <returns>All the remotes that are not domains.</returns>
        public static IEnumerable<IRemoteParty> GetAllLeafRemotes( this ApplicationIdentityService s )
        {
            foreach( var r in s.Remotes )
            {
                foreach( var rSub in r.GetAllLeafRemotes() )
                {
                    yield return rSub;
                }
            }
        }

        /// <summary>
        /// Gets the remotes that don't define a domain, including this one.
        /// </summary>
        /// <param name="p">This remote.</param>
        /// <returns>This party or the <see cref="IRemoteParty.DomainApplicationIdentity"/>'s remotes if this defines a domain.</returns>
        public static IEnumerable<IRemoteParty> GetAllLeafRemotes( this IRemoteParty p )
        {
            var d = p.DomainApplicationIdentity;
            if( d == null ) yield return p;
            else
            {
                foreach( var r in d.Remotes )
                {
                    yield return r;
                }
            }
        }
    }
}
