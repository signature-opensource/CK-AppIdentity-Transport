using CK.Core;
using System;
using System.Linq;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// The approval page of the System: a fact of a client application (<see cref="EnlistmentFact"/>), read where it is
/// needed. A System is a star around its Authentication Center: nothing is announced beyond one hop, the center reads
/// the page from the descriptions of its remotes and states its URL to the others (see <see cref="IPeeringAuthority"/>).
/// </summary>
public partial class TransportFeatureDriver
{
    /// <summary>
    /// The fact of a client application that is an approval page (see <see cref="ClientApplicationDescription.Facts"/>):
    /// its value is the path of the page, after the URL of the client application ("app-identity/enlist").
    /// </summary>
    public const string EnlistmentFact = "Enlistment";

    /// <summary>
    /// Gets the URL of the approval page of a description, or null: the URL of its client application that has the
    /// <see cref="EnlistmentFact"/>, followed by the value of the fact (the path of the page: exactly one non empty value).
    /// A party without public URL hosts no page: never a URL that can't be reached.
    /// </summary>
    /// <param name="d">The description.</param>
    /// <param name="owner">The full name of the party described (for the logs).</param>
    /// <returns>The URL of the page or null.</returns>
    public static string? GetEnlistmentPageUrl( PartyDescription d, string owner )
    {
        Throw.CheckNotNullArgument( d );
        if( d.PublicUrl == null ) return null;
        var page = d.ClientApplications.FirstOrDefault( c => c.Facts.Contains( EnlistmentFact ) );
        if( page == null ) return null;
        var values = page.Facts.Get( EnlistmentFact );
        if( values.Length != 1 || string.IsNullOrWhiteSpace( values[0] ) )
        {
            ActivityMonitor.StaticLogger.Error( $"The client application '{page.Name}' of '{owner}' has the \"{EnlistmentFact}\" fact with " +
                                                $"{values.Length} value(s) ({page.Facts}): exactly one value, the path of the approval page, is expected. No approval page." );
            return null;
        }
        return d.PublicUrl.GetLeftPart( UriPartial.Authority ) + page.RequestPath.TrimEnd( '/' ) + "/" + values[0].Trim( '/' );
    }

    /// <summary>
    /// Finds the URL of the approval page known by a local party: its own page, otherwise the page of the only direct
    /// remote of its System (same domain and environment) whose description has one. Several remotes with a page is an
    /// error (logged): there is no page. Null when the party knows no page.
    /// <para>
    /// The Authentication Center states the page it finds this way to the other parties (<see cref="EnlistmentUrlStatement"/>):
    /// in a star, every party is its remote.
    /// </para>
    /// </summary>
    /// <param name="local">The local party.</param>
    /// <returns>The URL of the page or null.</returns>
    public static string? FindEnlistmentPageUrl( ILocalParty local )
    {
        Throw.CheckNotNullArgument( local );
        var own = GetEnlistmentPageUrl( local.Description, local.FullName );
        if( own != null ) return own;
        string? found = null;
        string? host = null;
        foreach( var r in local.Remotes )
        {
            if( r.IsDestroyed || r.DomainName != local.DomainName || r.EnvironmentName != local.EnvironmentName ) continue;
            var u = GetEnlistmentPageUrl( r.Description, r.FullName );
            if( u == null ) continue;
            if( found != null )
            {
                ActivityMonitor.StaticLogger.Error( ActivityMonitor.Tags.SecurityCritical,
                                                    $"'{local.FullName}' sees two approval pages: '{host}' ({found}) and '{r.FullName}' ({u}). " +
                                                    $"A System has one approval page: none is used." );
                return null;
            }
            found = u;
            host = r.FullName;
        }
        return found;
    }
}
