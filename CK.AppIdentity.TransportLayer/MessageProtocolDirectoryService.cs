using CK.Core;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Central registration for <see cref="MessageProtocol"/>.
    /// </summary>
    public sealed class MessageProtocolDirectoryService : ISingletonAutoService
    {
        readonly ConcurrentDictionary<string, MessageProtocol> _protocols;

        /// <summary>
        /// Initializes a new empty directory.
        /// </summary>
        public MessageProtocolDirectoryService()
        {
            _protocols = new ConcurrentDictionary<string, MessageProtocol>();
        }

        /// <summary>
        /// Registers a protocol. 
        /// </summary>
        /// <param name="fullName">Protocol name. Must not be null, empty or white space.</param>
        /// <param name="isPartySpecific">True if this protocol is specific to the parties.</param>
        /// <returns>The unique registration.</returns>
        public MessageProtocol Register( string fullName, bool isPartySpecific = false )
        {
            Throw.CheckNotNullOrWhiteSpaceArgument( fullName );
            Throw.CheckArgument( fullName.Length <= MessageProtocol.FullNameMaxLength );
            if( fullName.Equals( MessageProtocol.ZeroProtocol.Name, StringComparison.OrdinalIgnoreCase ) )
            {
                return MessageProtocol.ZeroProtocol;
            }
            if( !TryParse( ref fullName, out var name, out var version ) )
            {
                Throw.ArgumentException( $"Invalid '{fullName}' protocol name." );
            }
            var registered = _protocols.AddOrUpdate( fullName, new MessageProtocol( fullName, name, version, isPartySpecific ), ( n, exist ) => exist );
            if( registered.IsPartySpecific != isPartySpecific )
            {
                Throw.ArgumentException( $"Protocol '{fullName}' is already registered with IsPartySpecific = {registered.IsPartySpecific}." );
            }
            return registered;
        }

        /// <summary>
        /// Tries to register a protocol: the name must be valid, not "0 Protocol" and no already
        /// registered protocol with same name exist with a different <see cref="MessageProtocol.IsPartySpecific"/>.
        /// </summary>
        /// <param name="fullName">Protocol name. Must not be null, empty or white space.</param>
        /// <param name="isPartySpecific">True if this protocol is specific to the parties.</param>
        /// <param name="registered">The registered message protocol on success.</param>
        /// <returns>True on success, false otherwise.</returns>
        public bool TryRegister( string fullName, bool isPartySpecific, [NotNullWhen(true)]out MessageProtocol? registered )
        {
            if( !string.IsNullOrWhiteSpace( fullName )
                && TryParse( ref fullName, out var name, out var version )
                && name != MessageProtocol.ZeroProtocol.Name )
            {
                var r = _protocols.AddOrUpdate( fullName, new MessageProtocol( fullName, name, version, isPartySpecific ), ( n, exist ) => exist );
                if( r.IsPartySpecific == isPartySpecific )
                {
                    registered = r;
                    return true;
                }
            }
            registered = null;
            return false;
        }

        internal bool TryRegister( IActivityMonitor monitor, string name, ushort version, bool isPartySpecific, [NotNullWhen(true)]out MessageProtocol? registered )
        {
            name = name.Trim();
            if( name.Length == 0 || name.Contains( '.' ) || name.Equals( MessageProtocol.ZeroProtocol.Name, StringComparison.OrdinalIgnoreCase ) )
            {
                monitor.Error( $"Unable to register invalid protocol name '{name}'." );
            }
            else
            {
                var fullName = FormatFullName( name, version );
                var r = _protocols.AddOrUpdate( fullName, new MessageProtocol( fullName, name, version, isPartySpecific ), ( n, exist ) => exist );
                if( r.IsPartySpecific == isPartySpecific )
                {
                    registered = r;
                    return true;
                }
                monitor.Error( $"Protocol '{fullName}' is already registered with IsPartySpecific = {r.IsPartySpecific}." );
            }
            registered = null;
            return false;
        }

        static bool TryParse( ref string fullName, out string name, out ushort version )
        {
            fullName = fullName.Trim();
            int idx = fullName.IndexOf( '.' );
            if( idx < 0 )
            {
                name = fullName;
                fullName = FormatFullName( name, version = 0 );
                return true;
            }
            if( idx > 0
                && idx < fullName.Length - 1
                && ushort.TryParse(fullName.AsSpan(idx), out version ) )
            {
                name = fullName.Substring(0, idx);
                return true;
            }
            name = string.Empty;
            version = 0;
            return false;
        }

        internal static string FormatFullName( string name, int version ) => $"{name}.{version}";

    }
}
