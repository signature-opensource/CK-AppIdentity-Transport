using CK.Core;

namespace CK.AppIdentity.AuthCenter;

/// <summary>
/// The "AuthCenter" asymmetric feature (see the asymmetric features of CK.AppIdentity): the "AllowFeatures" use
/// "AuthCenter" in the "Local" section of a local party and "AuthCenterRemote" on a remote.
/// <list type="bullet">
///   <item>
///   A local party that allows "AuthCenter" <b>is</b> its Authentication Center (the <c>LocalAuthCenterFeatureDriver</c>
///   of CK.AppIdentity.AuthCenter.Local). Its remotes that allow "AuthCenterRemote" are its remotes: they share its
///   <see cref="CrisAuthCenter"/>.
///   </item>
///   <item>
///   A local party that doesn't allow it uses <b>the</b> remote that allows "AuthCenterRemote", if any: this remote is
///   its Authentication Center (the <c>RemoteAuthCenterFeatureDriver</c> of CK.AppIdentity.AuthCenter.Remote). More than
///   one remote that allows "AuthCenterRemote" is a configuration error. A remote added later can be it.
///   </item>
/// </list>
/// The AuthCenter is a <b>singleton</b> asymmetric feature: there is one Authentication Center in a tenant (this is not
/// checked). The two sides can coexist in an application: the "AuthCenter" of a local party gives its role.
/// <para>
/// The local AuthCenter's settings are the "AuthCenter" section of its "Local" (see <c>AuthCenterOptions</c>). There is no
/// designation: an "AuthCenter" key on a remote, or an "AuthCenter" value that is not a section in a "Local" (like
/// <c>true</c>), is a configuration error. The Authentication Center must have the "KeyManagement" feature: its keys
/// verify the tokens. A remote Authentication Center that is destroyed leaves its local party without authentication:
/// the feature stays (features cannot be removed) and is no more <see cref="CrisAuthCenter.IsAvailable"/>.
/// </para>
/// </summary>
public static class AuthCenterFeature
{
    /// <summary>
    /// The feature name and the name of the settings section of a local Authentication Center (in its "Local"): "AuthCenter".
    /// </summary>
    public const string Name = "AuthCenter";

    /// <summary>
    /// The name of the route hosted by an Authentication Center (its target is its full name): every party of the System
    /// has a path to it, whatever its channels (see <see cref="PartyDescription.Routes"/>). Its key events are fetched
    /// along it by the parties that anchor it without a channel to it (the key directory).
    /// </summary>
    public const string RouteName = "AuthCenter";

    /// <summary>
    /// Checks that there is no designation: an "AuthCenter" key on a remote is an error, and so is an "AuthCenter" value
    /// of a "Local" that is not a section (the "AuthCenter" section of a "Local" is the settings of a local AuthCenter).
    /// Used by the two sides of the feature.
    /// </summary>
    /// <param name="monitor">The monitor.</param>
    /// <param name="party">The party to check.</param>
    /// <returns>True on success, false on error.</returns>
    public static bool CheckNoAuthCenterKey( IActivityMonitor monitor, IParty party )
    {
        if( party is ILocalParty local )
        {
            var settings = local.LocalConfiguration.Configuration.TryGetSection( Name );
            if( settings == null || settings.HasChildren ) return true;
            monitor.Error( $"Invalid '{settings.Path}' = '{settings.Value}': the \"AuthCenter\" section of a \"Local\" holds the settings of a local AuthCenter. "
                           + $"An AuthCenter is not designated: allow the \"AuthCenter\" feature." );
            return false;
        }
        var key = party.Configuration.Configuration.TryGetSection( Name );
        if( key == null ) return true;
        monitor.Error( $"Invalid '{key.Path}': an AuthCenter is not designated: allow the \"AuthCenterRemote\" feature for the remote that is the AuthCenter "
                       + $"(and its settings are its own, in its \"Local\")." );
        return false;
    }
}
