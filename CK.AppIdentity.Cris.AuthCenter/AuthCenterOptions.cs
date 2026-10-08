using CK.Core;
using System;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// The settings of a local Authentication Center, read from its "AuthCenter" configuration section (never inherited).
/// They are static: the configuration of an application identity never changes at runtime.
/// </summary>
public sealed class AuthCenterOptions
{
    /// <summary>
    /// The default options.
    /// </summary>
    public static readonly AuthCenterOptions Default = new AuthCenterOptions( TimeSpan.FromDays( 1 ), TimeSpan.FromMinutes( 5 ), TimeSpan.FromMinutes( 10 ) );

    AuthCenterOptions( TimeSpan sessionLifetime, TimeSpan criticalLifetime, TimeSpan tokenLifetime )
    {
        SessionLifetime = sessionLifetime;
        CriticalLifetime = criticalLifetime;
        TokenLifetime = tokenLifetime;
    }

    /// <summary>
    /// Gets the lifetime of a session: the <see cref="AuthenticationInfo.Expires"/> of a login.
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

    internal static AuthCenterOptions? Read( IActivityMonitor monitor, ImmutableConfigurationSection? section )
    {
        if( section == null ) return Default;
        bool success = true;
        var session = ReadTimeSpan( monitor, section, nameof( SessionLifetime ), Default.SessionLifetime, ref success );
        var critical = ReadTimeSpan( monitor, section, nameof( CriticalLifetime ), Default.CriticalLifetime, ref success );
        var token = ReadTimeSpan( monitor, section, nameof( TokenLifetime ), Default.TokenLifetime, ref success );
        if( !success ) return null;
        if( critical > session || token > session )
        {
            monitor.Error( $"Invalid '{section.Path}': the {nameof( CriticalLifetime )} ({critical}) and the {nameof( TokenLifetime )} ({token}) cannot exceed the {nameof( SessionLifetime )} ({session})." );
            return null;
        }
        return new AuthCenterOptions( session, critical, token );
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
