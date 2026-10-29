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
/// The "AuthCenter:CriticalLifetimes" sub-section is the core's (see <see cref="CriticalLifetimes"/>).
/// </para>
/// </summary>
public sealed class AuthCenterOptions
{
    /// <summary>
    /// The default options.
    /// </summary>
    public static readonly AuthCenterOptions Default = new AuthCenterOptions( TimeSpan.FromDays( 1 ),
                                                                             TimeSpan.FromMinutes( 5 ),
                                                                             TimeSpan.FromMinutes( 10 ),
                                                                             TimeSpan.FromMinutes( 1 ),
                                                                             new Dictionary<string, TimeSpan>( StringComparer.OrdinalIgnoreCase ) );

    /// <summary>
    /// The maximal <see cref="RefreshGraceWindow"/>: 5 minutes.
    /// </summary>
    public static readonly TimeSpan MaxRefreshGraceWindow = TimeSpan.FromMinutes( 5 );

    AuthCenterOptions( TimeSpan sessionLifetime,
                       TimeSpan criticalLifetime,
                       TimeSpan tokenLifetime,
                       TimeSpan refreshGraceWindow,
                       IReadOnlyDictionary<string, TimeSpan> criticalLifetimes )
    {
        SessionLifetime = sessionLifetime;
        CriticalLifetime = criticalLifetime;
        TokenLifetime = tokenLifetime;
        RefreshGraceWindow = refreshGraceWindow;
        CriticalLifetimes = criticalLifetimes;
    }

    /// <summary>
    /// Gets the lifetime of a session: the <see cref="AuthenticationInfo.Expires"/> of a login. The session slides: each
    /// refresh moves its end to this lifetime after the refresh.
    /// Defaults to 1 day.
    /// </summary>
    public TimeSpan SessionLifetime { get; }

    /// <summary>
    /// Gets the lifetime of the <see cref="AuthLevel.Critical"/> level after a login: the <see cref="AuthenticationInfo.CriticalExpires"/>.
    /// This is the default of the schemes that are not in <see cref="CriticalLifetimes"/>.
    /// Defaults to 5 minutes.
    /// </summary>
    public TimeSpan CriticalLifetime { get; }

    /// <summary>
    /// Gets the lifetime of the <see cref="AuthLevel.Critical"/> level of specific schemes ("AuthCenter:CriticalLifetimes:&lt;scheme&gt;").
    /// <see cref="TimeSpan.Zero"/> means that the scheme never elevates an actor to the Critical level (a remote provider
    /// that the deployment doesn't trust enough for instance).
    /// </summary>
    public IReadOnlyDictionary<string, TimeSpan> CriticalLifetimes { get; }

    /// <summary>
    /// Gets the lifetime of the <see cref="AuthLevel.Critical"/> level after a login with a scheme: its <see cref="CriticalLifetimes"/>
    /// or the <see cref="CriticalLifetime"/>.
    /// <para>
    /// The Critical level starts with the actual authentication of the user: a login whose authentication is older than
    /// this lifetime (a remote provider that didn't authenticate the user again) is at the <see cref="AuthLevel.Normal"/> level.
    /// </para>
    /// </summary>
    /// <param name="scheme">The login scheme.</param>
    /// <returns>The lifetime of the Critical level, <see cref="TimeSpan.Zero"/> when the scheme cannot elevate.</returns>
    public TimeSpan GetCriticalLifetime( string scheme )
    {
        return CriticalLifetimes.TryGetValue( scheme, out var lifetime ) ? lifetime : CriticalLifetime;
    }

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
        var criticalLifetimes = new Dictionary<string, TimeSpan>( StringComparer.OrdinalIgnoreCase );
        if( section.TryGetSection( nameof( CriticalLifetimes ) ) is { } lifetimes )
        {
            foreach( var l in lifetimes.GetChildren() )
            {
                if( l.Value == null || !TimeSpan.TryParse( l.Value, out var v ) || v < TimeSpan.Zero )
                {
                    monitor.Error( $"Invalid '{l.Path}' = '{l.Value}': a time span is expected (0 when the scheme never elevates to the Critical level)." );
                    success = false;
                }
                else
                {
                    criticalLifetimes[l.Key] = v;
                }
            }
        }
        foreach( var s in section.GetChildren() )
        {
            if( s.GetChildren().Any()
                && !s.Key.Equals( nameof( CriticalLifetimes ), StringComparison.OrdinalIgnoreCase )
                && !schemeKeys.Contains( s.Key, StringComparer.OrdinalIgnoreCase ) )
            {
                monitor.Error( $"The '{s.Path}' section belongs to no installed scheme family (is a package missing?). Installed: '{schemeKeys.Concatenate( "', '" )}'." );
                success = false;
            }
        }
        if( !success ) return null;
        if( critical > session || token > session || criticalLifetimes.Values.Any( l => l > session ) )
        {
            monitor.Error( $"Invalid '{section.Path}': the {nameof( CriticalLifetime )} ({critical}), the {nameof( CriticalLifetimes )} and the {nameof( TokenLifetime )} ({token}) cannot exceed the {nameof( SessionLifetime )} ({session})." );
            return null;
        }
        return new AuthCenterOptions( session, critical, token, grace, criticalLifetimes );
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
