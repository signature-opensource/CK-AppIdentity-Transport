using CK.Core;
using System;
using System.Collections.Generic;
using System.Linq;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// The settings of a local Authentication Center: its configuration model, <see cref="AuthCenterConfiguration"/> (the
/// "AuthCenter" section of the local party, key by key with its "Defaults"). They are static: the configuration of an
/// application identity never changes at runtime.
/// <para>
/// The other keys of the section are the options of the <see cref="LocalAuthCenterFeatureDriver"/>: the scheme families
/// ("AuthCenter:Oidc", see <see cref="IAuthCenterSchemeFamilyOption"/>) and the other options; any other key is an error
/// (the model is closed: an option whose package is missing is an unknown key).
/// </para>
/// </summary>
public sealed class AuthCenterOptions
{
    /// <summary>
    /// The default options.
    /// </summary>
    public static readonly AuthCenterOptions Default = Create( new AuthCenterConfiguration() );

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

    /// <summary>
    /// Creates the settings from the (checked) configuration model.
    /// </summary>
    /// <param name="c">The configuration.</param>
    /// <returns>The settings.</returns>
    internal static AuthCenterOptions Create( AuthCenterConfiguration c )
    {
        return new AuthCenterOptions( c.SessionLifetime,
                                      c.CriticalLifetime,
                                      c.TokenLifetime,
                                      c.RefreshGraceWindow,
                                      new Dictionary<string, TimeSpan>( c.CriticalLifetimes, StringComparer.OrdinalIgnoreCase ) );
    }
}

/// <summary>
/// The configuration of a local Authentication Center (the "AuthCenter" section of its "Local"): the lifetimes of its
/// sessions, of their Critical level and of the tokens. The other keys of the section are its options.
/// </summary>
[ConfigurationModel]
public sealed class AuthCenterConfiguration : IConfigurationModel
{
    /// <summary>
    /// Gets the lifetime of a session (it slides on each refresh). Defaults to 1 day.
    /// </summary>
    public TimeSpan SessionLifetime { get; init; } = TimeSpan.FromDays( 1 );

    /// <summary>
    /// Gets the lifetime of the Critical level of a session (after a login that proves the user's presence). Defaults to
    /// 5 minutes.
    /// </summary>
    public TimeSpan CriticalLifetime { get; init; } = TimeSpan.FromMinutes( 5 );

    /// <summary>
    /// Gets the lifetime of the Critical level per scheme ("Basic", "Oidc.Google"...), instead of <see cref="CriticalLifetime"/>:
    /// 0 when the scheme never elevates to the Critical level.
    /// </summary>
    public IReadOnlyDictionary<string, TimeSpan> CriticalLifetimes { get; init; } = new Dictionary<string, TimeSpan>( StringComparer.OrdinalIgnoreCase );

    /// <summary>
    /// Gets the lifetime of the tokens. Defaults to 10 minutes.
    /// </summary>
    public TimeSpan TokenLifetime { get; init; } = TimeSpan.FromMinutes( 10 );

    /// <summary>
    /// Gets the window during which the previous secrets of a refreshed session are still accepted (0 disables it).
    /// Defaults to 1 minute, at most <see cref="AuthCenterOptions.MaxRefreshGraceWindow"/>.
    /// </summary>
    public TimeSpan RefreshGraceWindow { get; init; } = TimeSpan.FromMinutes( 1 );

    /// <inheritdoc />
    public void Validate( IConfigurationValidationContext context )
    {
        void Positive( TimeSpan v, string name )
        {
            if( v <= TimeSpan.Zero ) context.Error( $"'{context.Path}:{name}' = '{v}': a positive time span is expected." );
        }
        Positive( SessionLifetime, nameof( SessionLifetime ) );
        Positive( CriticalLifetime, nameof( CriticalLifetime ) );
        Positive( TokenLifetime, nameof( TokenLifetime ) );
        if( RefreshGraceWindow < TimeSpan.Zero || RefreshGraceWindow > AuthCenterOptions.MaxRefreshGraceWindow )
        {
            context.Error( $"'{context.Path}:{nameof( RefreshGraceWindow )}' = '{RefreshGraceWindow}': a time span between 0 (disabled) and {AuthCenterOptions.MaxRefreshGraceWindow} is expected." );
        }
        foreach( var (scheme, lifetime) in CriticalLifetimes )
        {
            if( lifetime < TimeSpan.Zero )
            {
                context.Error( $"'{context.Path}:{nameof( CriticalLifetimes )}:{scheme}' = '{lifetime}': a time span is expected (0 when the scheme never elevates to the Critical level)." );
            }
        }
        if( CriticalLifetime > SessionLifetime || TokenLifetime > SessionLifetime || CriticalLifetimes.Values.Any( l => l > SessionLifetime ) )
        {
            context.Error( $"'{context.Path}': the {nameof( CriticalLifetime )} ({CriticalLifetime}), the {nameof( CriticalLifetimes )} and the {nameof( TokenLifetime )} ({TokenLifetime}) cannot exceed the {nameof( SessionLifetime )} ({SessionLifetime})." );
        }
    }
}
