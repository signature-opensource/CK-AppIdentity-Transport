using CK.Core;
using System.Collections.Generic;
using System.Linq;
using System;

namespace CK.AppIdentity.TransportLayer
{
    public partial class TransportFeatureDriver
    {
        bool ResolveAdresses( IActivityMonitor monitor,
                              IRemoteParty r,
                              out IReadOnlyCollection<TransportTypeAddress>? listen,
                              out TransportTypeAddress? target )
        {
            // If the Address is set, it must be parseable.
            var a = r.Address;
            if( a != null )
            {
                var section = r.Configuration.Configuration.TryGetSection( "Address" );
                Throw.DebugAssert( section != null );
                listen = null;
                target = ParseTypedAddress( monitor, a, section );
                return target != null;
            }
            // No Address: lookup for the ListeningAddress.
            // ReadListeningAddresses returns true if no error occurred but the address map can be null.
            target = null;
            listen = ResolveListeningAddresses( monitor, r );
            return listen != null;
        }

        IReadOnlyCollection<TransportTypeAddress>? ResolveListeningAddresses( IActivityMonitor monitor, IParty party )
        {
            if( !ReadListeningAddresses( monitor, party.Configuration.Configuration, out var available ) )
            {
                return null;
            }
            Throw.DebugAssert( "If there is a map, it is not empty.", available == null || available.Count > 0 );
            // If there is a single listening address, we are done: there is no ambiguity.
            if( available != null && available.Count == 1 )
            {
                return available.Values;
            }
            // If there is no "ListeningAddress" at all, consider the default tcp listening address
            // bound to the root ApplicationIdentityService configuration.
            var rootConfiguration = party.ApplicationIdentityService.Configuration.Configuration;
            if( available == null )
            {
                var tcpDef = _tcp.DefaultListeningAddress;
                Throw.DebugAssert( tcpDef != null );
                return new[] { new TransportTypeAddress( _tcp, rootConfiguration, tcpDef ) };
            }
            // If there is more than one type of Transport, inject the defaults of all transport type (if supported and
            // if no address exist for them) and let "ListeningTypes" decides or use the 'all' if "ListeningTypes" is missing.
            foreach( var t in _transportTypes )
            {
                if( !available.ContainsKey( t ) )
                {
                    var def = t.DefaultListeningAddress;
                    if( def != null )
                    {
                        available.Add( t, new TransportTypeAddress( t, rootConfiguration, def ) );
                    }
                }
            }
            // Handling "ListeningTypes". This normally applies to Remote (not to a Local party) but this doesn't
            // cost much to equally applies it a Local configuration level: this enables a transport Type to be an
            // "opt-in one"... It's overkill but corresponds to simpler code.
            var listeningTypesSection = party.Configuration.Configuration.TryLookupSection( "ListeningTypes" );
            if( listeningTypesSection == null )
            {
                monitor.Warn( $"No \"ListeningTypes\" configuration for Party '{party.FullName}'. " +
                              $"Using all available ListeningAddress: {available.Values.Select( a => a.ToString() ).Concatenate()}." );
                return available.Values;
            }
            var listeningTypeNames = listeningTypesSection.ReadUniqueStringSet( monitor, StringComparer.OrdinalIgnoreCase );
            if( listeningTypeNames == null ) return null;
            if( listeningTypeNames.Count == 0 )
            {
                monitor.Error( $"Invalid '{listeningTypesSection.Path}' empty configuration for Party '{party.FullName}'. " +
                               $"At least one of '{_transportTypes.Select( t => t.TypeName ).Concatenate( "','" )}' or 'all' must be specified.'" );
                return null;
            }
            // Detecting invalid or unavailable type names and the 'all' occurrence,
            // or builds the set of final TransportTypeAddress.
            List<TransportTypeAddress>? final = null;
            foreach( var t in listeningTypeNames )
            {
                if( t.Equals( "all", StringComparison.OrdinalIgnoreCase ) )
                {
                    return available.Values;
                }
                var exist = available.Values.FirstOrDefault( exist => exist.Type.TypeName.Equals( t, StringComparison.OrdinalIgnoreCase ) );
                if( exist == null )
                {
                    monitor.Error( $"Invalid value '{t}' in '{listeningTypesSection.Path}' for Party '{party.FullName}'.{Environment.NewLine}" +
                                   $"Available transport types here are: '{available.Values.Select( t => t.Type.TypeName ).Concatenate( "','" )}'." );
                    return null;
                }
                final ??= new List<TransportTypeAddress>();
                final.Add( exist );
            }
            return final;
        }

        bool ReadListeningAddresses( IActivityMonitor monitor,
                                     ImmutableConfigurationSection configuration,
                                     out Dictionary<ITransportTypeService, TransportTypeAddress>? result )
        {
            result = null;
            List<ITransportTypeService>? locally = null;
            foreach( var config in configuration.LookupAllSection( "ListeningAddress" ) )
            {
                var onLevel = config.ReadStringArray( monitor );
                if( onLevel == null ) return false;
                if( onLevel.Length > 0 )
                {
                    if( locally == null ) locally = new List<ITransportTypeService>();
                    else locally.Clear();
                    foreach( var raw in onLevel )
                    {
                        var parsed = ParseTypedAddress( monitor, raw, config );
                        if( parsed == null ) return false;
                        if( locally.Contains( parsed.Type ) )
                        {
                            monitor.Error( $"Invalid '{configuration.Path}': more than one address for '{parsed.Type.TypeName}' transport type." );
                            return false;
                        }
                        result ??= new Dictionary<ITransportTypeService, TransportTypeAddress>();
                        result[parsed.Type] = parsed;
                    }
                }
            }
            return true;
        }

        TransportTypeAddress? ParseTypedAddress( IActivityMonitor monitor, string s, ImmutableConfigurationSection section )
        {
            ITransportTypeService? transport = null;
            ReadOnlySpan<char> typed = s.AsSpan();
            int idx = s.IndexOf( ':' );
            if( idx > 0 )
            {
                var p = s.AsSpan( 0, idx );
                foreach( var t in _transportTypes )
                {
                    if( p.Equals( t.TypeName, StringComparison.OrdinalIgnoreCase ) )
                    {
                        typed = s.AsSpan( idx + 1 );
                        transport = t;
                        break;
                    }
                }
                if( transport == null )
                {
                    monitor.Error( $"Transport type '{p}' not found for '{section.Path}', address: '{s}'." );
                    return null;
                }
            }
            else
            {
                transport = _tcp;
            }
            return transport.ParseAddress( monitor, typed, section );
        }

    }
}
