using CK.AppIdentity.KeyManagement;
using CK.Core;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CK.AppIdentity.Cris.AuthCenter;

/// <summary>
/// Manages the opt-in "AuthCenter" feature: "AllowFeatures" must contain "AuthCenter" (in the "Local" section of a local
/// party, on a remote, or in a "Defaults" that applies to them).
/// <para>
/// The Authentication Center of a <see cref="ILocalParty"/> is given by the role of the application (it references
/// CK.AppIdentity.Cris.AuthCenter.Local or CK.AppIdentity.Cris.AuthCenter.Remote) and by the feature:
/// <list type="bullet">
///   <item>
///   <b>Local side</b> (this application is an Authentication Center): a local party that allows the feature <b>is</b> its
///   Authentication Center. Its remotes that allow the feature are its remotes: they share its <see cref="CrisAuthCenter"/>.
///   </item>
///   <item>
///   <b>Remote side</b> (this application is a remote of an Authentication Center): a local party that allows the feature
///   uses <b>the</b> remote that allows it: this remote is its Authentication Center. More than one remote that allows the
///   feature is a configuration error (a "Defaults" that allows the feature applies to every remote below it).
///   </item>
/// </list>
/// The local AuthCenter's settings are the "AuthCenter" section of its "Local" (see <c>AuthCenterOptions</c>). The former
/// designation (<c>"AuthCenter": true</c> on a party) is a configuration error: allowing the feature is enough.
/// </para>
/// <para>
/// The rules:
/// <list type="bullet">
///   <item>
///   The Authentication Center is defined with its local party: a remote added later (<see cref="ILocalParty.AddRemoteAsync"/>)
///   cannot be the Authentication Center (on the Local side, it receives the existing feature when it allows it).
///   </item>
///   <item>
///   A remote Authentication Center that is destroyed leaves its local party without authentication: the feature
///   stays (features cannot be removed) and is no more <see cref="CrisAuthCenter.IsAvailable"/>.
///   </item>
///   <item>The Authentication Center must have the "KeyManagement" feature: its keys verify the tokens.</item>
/// </list>
/// </para>
/// <para>
/// This driver is the core shared by the two sides of the feature: the <c>LocalAuthCenterFeatureDriver</c>
/// (CK.AppIdentity.Cris.AuthCenter.Local) and the <c>RemoteAuthCenterFeatureDriver</c> (CK.AppIdentity.Cris.AuthCenter.Remote).
/// An application has one role: it references one of them.
/// </para>
/// </summary>
public sealed class AuthCenterFeatureDriver : ApplicationIdentityFeatureDriver
{
    bool? _isLocalSide;

    /// <summary>
    /// The feature name and the name of the settings section of a local Authentication Center (in its "Local"): "AuthCenter".
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

    // Called by the constructor of the side driver: the role of the application.
    internal void SetSide( bool isLocal ) => _isLocalSide = isLocal;

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
        if( !CheckNoAuthCenterKey( context.Monitor, remote ) ) return Task.FromResult( false );
        if( IsAllowedFeature( remote ) )
        {
            var f = remote.Owner.GetFeature<CrisAuthCenter>();
            if( _isLocalSide == true )
            {
                if( f != null ) remote.AddFeature( f );
            }
            else
            {
                context.Monitor.Error( $"Remote '{remote}' cannot be the AuthCenter of '{remote.Owner}': the AuthCenter is defined with its local party, not by a remote added later." );
                return Task.FromResult( false );
            }
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
        bool success = CheckNoAuthCenterKey( monitor, local );
        foreach( var r in local.Remotes )
        {
            success &= CheckNoAuthCenterKey( monitor, r );
        }
        if( !success ) return false;
        var allowingRemotes = local.Remotes.Where( IsAllowedFeature ).ToList();
        if( !IsAllowedFeature( local ) )
        {
            if( allowingRemotes.Count > 0 )
            {
                monitor.Warn( $"The '{FeatureName}' feature is allowed for the remotes '{allowingRemotes.Select( r => r.ToString() ).Concatenate( "', '" )}' but not for '{local}' (in its \"Local\"): '{local}' has no authentication." );
            }
            return true;
        }
        if( _isLocalSide == null )
        {
            monitor.Error( $"The '{FeatureName}' feature is allowed for '{local}' but the application has no role: it must reference CK.AppIdentity.Cris.AuthCenter.Local (it is the AuthCenter) or CK.AppIdentity.Cris.AuthCenter.Remote (it is a remote of an AuthCenter)." );
            return false;
        }
        IParty authCenter;
        if( _isLocalSide.Value )
        {
            authCenter = local;
        }
        else
        {
            if( allowingRemotes.Count == 0 )
            {
                monitor.Warn( $"The '{FeatureName}' feature is allowed for '{local}' but for none of its remotes: '{local}' has no AuthCenter, it has no authentication." );
                return true;
            }
            if( allowingRemotes.Count > 1 )
            {
                monitor.Error( $"'{local}' can have only one AuthCenter but the '{FeatureName}' feature is allowed for the remotes '{allowingRemotes.Select( r => r.ToString() ).Concatenate( "', '" )}'. "
                               + $"Allow it only for the AuthCenter remote (a \"Defaults\" that allows it applies to every remote below it)." );
                return false;
            }
            authCenter = allowingRemotes[0];
        }
        // Its keys verify the tokens. A remote may not be pinned yet: Verify refuses until it is.
        if( authCenter.GetFeature<IPartyKeys>() == null )
        {
            monitor.Error( $"'{authCenter}' cannot be the AuthCenter of '{local}': it has no 'KeyManagement' feature (its keys verify the tokens)." );
            return false;
        }
        var f = new CrisAuthCenter( local, authCenter );
        local.AddFeature( f );
        foreach( var r in allowingRemotes )
        {
            r.AddFeature( f );
        }
        monitor.Info( $"{f} is available." );
        return true;
    }

    // The former designation ("AuthCenter": true on a party) is an error: allowing the feature is enough.
    // The "AuthCenter" section of a "Local" is the settings of a local AuthCenter: it must be a section.
    static bool CheckNoAuthCenterKey( IActivityMonitor monitor, IParty party )
    {
        if( party is ILocalParty local )
        {
            var settings = local.LocalConfiguration.Configuration.TryGetSection( ConfigurationKey );
            if( settings == null || settings.HasChildren ) return true;
            monitor.Error( $"Invalid '{settings.Path}' = '{settings.Value}': the \"AuthCenter\" section of a \"Local\" holds the settings of a local AuthCenter. "
                           + $"An AuthCenter is not designated: allow the \"AuthCenter\" feature." );
            return false;
        }
        var key = party.Configuration.Configuration.TryGetSection( ConfigurationKey );
        if( key == null ) return true;
        monitor.Error( $"Invalid '{key.Path}': an AuthCenter is not designated, allow the \"AuthCenter\" feature for the remote that is the AuthCenter "
                       + $"(and its settings are its own, in its \"Local\")." );
        return false;
    }
}
