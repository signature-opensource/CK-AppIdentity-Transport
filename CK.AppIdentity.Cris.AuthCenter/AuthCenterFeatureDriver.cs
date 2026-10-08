using CK.AppIdentity.KeyManagement;
using CK.Core;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// Manages the opt-in "AuthCenter" feature: to activate it, "AllowFeatures" must contain "AuthCenter".
/// <para>
/// The Authentication Center of a <see cref="ILocalParty"/> is the local party itself or one of its remotes: the party whose
/// own configuration has an "AuthCenter" key (true, or a section that will hold its settings). This key is read on the
/// party itself, it is never inherited. A <see cref="CrisAuthCenter"/> is then shared by the local party and all its remotes
/// that allow the feature.
/// </para>
/// <para>
/// The rules:
/// <list type="bullet">
///   <item>There is at most one Authentication Center per local party: two of them is a configuration error.</item>
///   <item>
///   The Authentication Center is defined with its local party: a remote added later (<see cref="ILocalParty.AddRemoteAsync"/>)
///   cannot be the Authentication Center (it receives the existing feature).
///   </item>
///   <item>
///   A remote Authentication Center that is destroyed leaves its local party without authentication: the feature
///   stays (features cannot be removed) and is no more <see cref="CrisAuthCenter.IsAvailable"/>.
///   </item>
///   <item>Designating an Authentication Center where the feature is not allowed is a configuration error.</item>
///   <item>The Authentication Center must have the "KeyManagement" feature: its keys verify the tokens.</item>
/// </list>
/// </para>
/// </summary>
public sealed class AuthCenterFeatureDriver : ApplicationIdentityFeatureDriver
{
    /// <summary>
    /// The configuration key that designates the Authentication Center: "AuthCenter".
    /// </summary>
    public const string ConfigurationKey = "AuthCenter";

    /// <summary>
    /// Initializes a new <see cref="AuthCenterFeatureDriver"/>.
    /// </summary>
    /// <param name="s">The application identity service.</param>
    /// <param name="keys">
    /// The key management: the keys of the Authentication Center verify its tokens (it must be set up before this driver).
    /// </param>
    public AuthCenterFeatureDriver( ApplicationIdentityService s, KeyManagementFeatureDriver keys )
        : base( s, isAllowedByDefault: false )
    {
    }

    /// <inheritdoc />
    protected override Task<bool> SetupAsync( FeatureLifetimeContext context )
    {
        bool success = true;
        foreach( var local in context.GetAllLocals() )
        {
            success &= PlugLocal( context.Monitor, local );
        }
        return Task.FromResult( success );
    }

    /// <inheritdoc />
    protected override Task<bool> SetupDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party )
    {
        if( party is ILocalParty local )
        {
            return Task.FromResult( PlugLocal( context.Monitor, local ) );
        }
        var remote = (IRemoteParty)party;
        if( !IsDesignated( context.Monitor, remote, out bool designated ) ) return Task.FromResult( false );
        if( designated )
        {
            context.Monitor.Error( $"Remote '{remote}' cannot be the AuthCenter of '{remote.Owner}': the AuthCenter is defined with its local party, not by a remote added later." );
            return Task.FromResult( false );
        }
        if( IsAllowedFeature( remote ) && remote.Owner.GetFeature<CrisAuthCenter>() is CrisAuthCenter f )
        {
            remote.AddFeature( f );
        }
        return Task.FromResult( true );
    }

    /// <inheritdoc />
    protected override Task TeardownDynamicRemoteAsync( FeatureLifetimeContext context, IOwnedParty party )
    {
        // A destroyed tenant domain takes its AuthCenter (and all its remotes) with it.
        // A destroyed remote that is the AuthCenter of a living local party is an issue.
        if( party is IRemoteParty remote
            && remote.Owner.GetFeature<CrisAuthCenter>() is CrisAuthCenter f
            && f.AuthCenter == remote )
        {
            context.Monitor.Error( $"The AuthCenter '{remote}' has been destroyed: authentication is no more available for '{remote.Owner}'." );
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    protected override Task TeardownAsync( FeatureLifetimeContext context ) => Task.CompletedTask;

    bool PlugLocal( IActivityMonitor monitor, ILocalParty local )
    {
        // Collects the designated parties (the local party first) and checks all of them.
        var designated = new List<IParty>();
        bool success = CollectDesignated( monitor, local, designated );
        foreach( var r in local.Remotes )
        {
            success &= CollectDesignated( monitor, r, designated );
        }
        if( !success ) return false;

        bool isAllowed = IsAllowedFeature( local );
        if( designated.Count == 0 )
        {
            if( isAllowed )
            {
                monitor.Warn( $"The '{FeatureName}' feature is allowed for '{local}' but no party is its AuthCenter (no '{ConfigurationKey}' configuration): '{local}' has no authentication." );
            }
            return true;
        }
        if( designated.Count > 1 )
        {
            monitor.Error( $"'{local}' can have only one AuthCenter: '{designated.Select( p => p.ToString() ).Concatenate( "', '" )}' are configured with '{ConfigurationKey}'." );
            return false;
        }
        var authCenter = designated[0];
        if( !isAllowed || !IsAllowedFeature( authCenter ) )
        {
            monitor.Error( $"'{authCenter}' is configured with '{ConfigurationKey}' but the '{FeatureName}' feature is not allowed for '{(isAllowed ? authCenter : local)}'." );
            return false;
        }
        // Its keys verify the tokens. A remote may not be pinned yet: Verify refuses until it is.
        if( authCenter.GetFeature<IPartyKeys>() == null )
        {
            monitor.Error( $"'{authCenter}' cannot be the AuthCenter of '{local}': it has no 'KeyManagement' feature (its keys verify the tokens)." );
            return false;
        }
        // The settings are the ones of a local AuthCenter: a remote one has its own.
        var settings = authCenter.Configuration.Configuration.TryGetSection( ConfigurationKey );
        if( settings != null && !settings.GetChildren().Any() ) settings = null;
        LocalAuthCenter? localCenter = null;
        if( authCenter == local )
        {
            var options = AuthCenterOptions.Read( monitor, settings );
            if( options == null ) return false;
            localCenter = new LocalAuthCenter( local, options );
        }
        else if( settings != null )
        {
            monitor.Warn( $"The '{settings.Path}' settings are ignored: '{authCenter}' is a remote AuthCenter (its settings are its own)." );
        }
        var f = new CrisAuthCenter( local, authCenter, localCenter );
        local.AddFeature( f );
        foreach( var r in local.Remotes )
        {
            if( IsAllowedFeature( r ) ) r.AddFeature( f );
        }
        monitor.Info( $"{f} is available." );
        return true;
    }

    static bool CollectDesignated( IActivityMonitor monitor, IParty party, List<IParty> designated )
    {
        if( !IsDesignated( monitor, party, out bool isDesignated ) ) return false;
        if( isDesignated ) designated.Add( party );
        return true;
    }

    // Reads the party's own "AuthCenter" configuration (never inherited): true or a section designates it.
    // Returns false on an invalid value (the error is logged).
    static bool IsDesignated( IActivityMonitor monitor, IParty party, out bool designated )
    {
        designated = false;
        var section = party.Configuration.Configuration.TryGetSection( ConfigurationKey );
        if( section == null ) return true;
        if( section.GetChildren().Any() )
        {
            designated = true;
            return true;
        }
        if( bool.TryParse( section.Value, out designated ) ) return true;
        monitor.Error( $"Invalid '{section.Path}' = '{section.Value}': expected true, false or a configuration section." );
        return false;
    }
}
