using CK.Core;
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
        public static T? GetFeature<T>( this IParty p ) => p.Features.OfType<T>().FirstOrDefault();

        /// <summary>
        /// Gets the first object feature that is a <typeparamref name="T"/> or throws
        /// an <see cref="InvalidOperationException"/>
        /// </summary>
        /// <typeparam name="T">The feature type.</typeparam>
        /// <param name="p">This party.</param>
        /// <returns>The feature.</returns>
        public static T GetRequiredFeature<T>( this IParty p )
        {
            var feature = p.Features.OfType<T>().FirstOrDefault();
            if( feature == null ) Throw.InvalidOperationException( $"Unable to find a feature '{typeof(T).ToCSharpName()}' in party '{p.FullName}'." );
            return feature;
        }
    }
}
