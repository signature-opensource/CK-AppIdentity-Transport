using CK.Cris;
using System.Collections.Generic;

namespace CK.AppIdentity.Cris;

/// <summary>
/// What the channels need from the Cris models, computed once by the <see cref="CrisChannelFeatureDriver"/> and shared by
/// every <see cref="CrisChannelFeature"/>: nothing is looked up nor reflected per message.
/// </summary>
sealed class CrisChannelModels
{
    readonly HashSet<string> _internal;
    readonly HashSet<string> _dispatched;

    public CrisChannelModels( CrisDirectory directory )
    {
        _internal = new HashSet<string>();
        _dispatched = new HashSet<string>();
        var inside = new List<string>();
        var outside = new List<string>();
        foreach( var m in directory.CrisPocoModels )
        {
            if( typeof( IPartyRoutedCommand ).IsAssignableFrom( m.CommandType ) ) RoutedCommand = m;
            if( m.Exposure == CrisExposure.Internal ) _internal.Add( m.PocoName );
            if( !m.IsHandled
                && !typeof( ICommandTargetParty ).IsAssignableFrom( m.CommandType )
                && !typeof( ICommandEndpointOnly ).IsAssignableFrom( m.CommandType ) )
            {
                _dispatched.Add( m.PocoName );
            }
        }
        foreach( var m in directory.CrisPocoModels )
        {
            if( IsAcceptedFromRemote( m, insideSystem: true ) ) inside.Add( m.PocoName );
            if( IsAcceptedFromRemote( m, insideSystem: false ) ) outside.Add( m.PocoName );
        }
        AcceptedFromInside = inside;
        AcceptedFromOutside = outside;
    }

    /// <summary>
    /// Gets the model of the <see cref="IPartyRoutedCommand"/>, null when it is not registered.
    /// </summary>
    public ICrisPocoModel? RoutedCommand { get; private set; }

    /// <summary>
    /// Gets the names of the commands accepted from a remote inside the System.
    /// </summary>
    public IReadOnlyList<string> AcceptedFromInside { get; }

    /// <summary>
    /// Gets the names of the commands accepted from a remote outside the System.
    /// </summary>
    public IReadOnlyList<string> AcceptedFromOutside { get; }

    /// <summary>
    /// Gets whether a name is the one of an <see cref="CrisExposure.Internal"/> model of this application.
    /// </summary>
    public bool IsInternal( string name ) => _internal.Contains( name );

    /// <summary>
    /// Gets whether a name is the one of a command that has no local handler and is dispatched (neither a party command,
    /// routed by its target, nor an endpoint-only one): it must be accepted by one remote only.
    /// </summary>
    public bool IsDispatched( string name ) => _dispatched.Contains( name );

    /// <summary>
    /// See <see cref="CrisChannelFeature.IsAcceptedFromRemote(ICrisPocoModel)"/>.
    /// </summary>
    public bool IsAcceptedFromRemote( ICrisPocoModel model, bool insideSystem )
    {
        // The routed command has no handler: the channel handles it (see IPartyRoutedCommand). It is [Internal].
        if( model.PocoName == RoutedCommand?.PocoName ) return insideSystem;
        return model.Kind is CrisPocoKind.Command or CrisPocoKind.CommandWithResult
               && model.IsHandled
               && model.Exposure switch
               {
                   CrisExposure.Public => true,
                   CrisExposure.Internal => insideSystem,
                   _ => false
               };
    }
}
