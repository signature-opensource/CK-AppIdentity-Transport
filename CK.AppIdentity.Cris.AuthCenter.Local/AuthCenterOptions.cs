using CK.Core;
using System;
using System.Collections.Generic;
using System.Linq;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// The settings of a local Authentication Center, read from its "AuthCenter" configuration section (never inherited).
/// They are static: the configuration of an application identity never changes at runtime.
/// <para>
/// The sub-sections belong to the scheme families ("AuthCenter:Oidc"...): each one is read by its package, and a
/// sub-section that no installed package declares (see <see cref="IAuthCenterSchemeConfiguration"/>) is an error.
/// </para>
/// </summary>
public sealed class AuthCenterOptions
{
    /// <summary>
    /// The default options.
    /// </summary>
    public static readonly AuthCenterOptions Default = new AuthCenterOptions( TimeSpan.FromDays( 1 ), TimeSpan.FromMinutes( 5 ), TimeSpan.FromMinutes( 10 ), TimeSpan.FromMinutes( 1 ) );

    /// <summary>
    /// The maximal <see cref="RefreshGraceWindow"/>: 5 minutes.
    /// </summary>
    public static readonly TimeSpan MaxRefreshGraceWindow = TimeSpan.FromMinutes( 5 );

    AuthCenterOptions( TimeSpan sessionLifetime, TimeSpan criticalLifetime, TimeSpan tokenLifetime, TimeSpan refreshGraceWindow )
    {
        SessionLifetime = sessionLifetime;
        CriticalLifetime = criticalLifetime;
        TokenLifetime = tokenLifetime;
        RefreshGraceWindow = refreshGraceWindow;
    }

    /// <summary>
    /// Gets the lifetime of a session: the <see cref="AuthenticationInfo.Expires"/> of a login. The session slides: each
    /// refresh moves its end to this lifetime after the refresh.
    /// Defaults to 1 day.
    /// </summary>
    public TimeSpan SessionLifetime { get; }

    /// <summary>
    /// Gets the lifetime of the <see cref="AuthLevel.Critical"/> level after a login: the <see cref="AuthenticationInfo.CriticalExpires"/>.
    /// Defaults to 5 minutes.
    /// </summary>
    public TimeSpan CriticalLifetime { get; }

    /// <summary>
    /// Gets the lifetime of a token. Tokens are verified locally (without the session store): a revoked session is
    /// usable until its token expires. Defaults to 10 minutes.
    /// </summary>
    public TimeSpan TokenLifetime { get; }

    /// <summary>
    /// Gets the time during which the previous secrets of a session are still accepted, once, after a rotation (a refresh,
    /// an impersonation): when the answer of a rotation is lost (a dropped connection, a remote's dispatch that timed out while
    /// the Authentication Center completed), the caller retries with its previous secrets instead of having its session
    /// revoked. It must cover the dispatch timeout (30 seconds) and the client's first retries.
    /// <para>
    /// Defaults to 1 minute, at most <see cref="MaxRefreshGraceWindow"/>. <see cref="TimeSpan.Zero"/> disables it: the
    /// previous secrets are then a reuse, the session is revoked.
    /// </para>
    /// </summary>
    public TimeSpan RefreshGraceWindow { get; }

    internal static AuthCenterOptions? Read( IActivityMonitor monitor, ImmutableConfigurationSection? section, IReadOnlyCollection<string> schemeKeys )
    {
        if( section == null ) return Default;
        bool success = true;
        var session = ReadTimeSpan( monitor, section, nameof( SessionLifetime ), Default.SessionLifetime, ref success );
        var critical = ReadTimeSpan( monitor, section, nameof( CriticalLifetime ), Default.CriticalLifetime, ref success );
        var token = ReadTimeSpan( monitor, section, nameof( TokenLifetime ), Default.TokenLifetime, ref success );
        var grace = Default.RefreshGraceWindow;
        if( section[nameof( RefreshGraceWindow )] is string g )
        {
            if( !TimeSpan.TryParse( g, out grace ) || grace < TimeSpan.Zero || grace > MaxRefreshGraceWindow )
            {
                monitor.Error( $"Invalid '{section.Path}:{nameof( RefreshGraceWindow )}' = '{g}': a time span between 0 (disabled) and {MaxRefreshGraceWindow} is expected." );
                success = false;
            }
        }
        foreach( var s in section.GetChildren() )
        {
            if( s.GetChildren().Any() && !schemeKeys.Contains( s.Key, StringComparer.OrdinalIgnoreCase ) )
            {
                monitor.Error( $"The '{s.Path}' section belongs to no installed scheme family (is a package missing?). Installed: '{schemeKeys.Concatenate( "', '" )}'." );
                success = false;
            }
        }
        if( !success ) return null;
        if( critical > session || token > session )
        {
            monitor.Error( $"Invalid '{section.Path}': the {nameof( CriticalLifetime )} ({critical}) and the {nameof( TokenLifetime )} ({token}) cannot exceed the {nameof( SessionLifetime )} ({session})." );
            return null;
        }
        return new AuthCenterOptions( session, critical, token, grace );
    }

    static TimeSpan ReadTimeSpan( IActivityMonitor monitor, ImmutableConfigurationSection section, string key, TimeSpan defaultValue, ref bool success )
    {
        var s = section[key];
        if( s == null ) return defaultValue;
        if( TimeSpan.TryParse( s, out var v ) && v > TimeSpan.Zero ) return v;
        monitor.Error( $"Invalid '{section.Path}:{key}' = '{s}': a positive time span is expected." );
        success = false;
        return defaultValue;
    }
}
