using CK.Core;
using System;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Central registration for <see cref="MessageProtocol"/>.
    /// </summary>
    public sealed class MessageProtocolDirectoryService : ISingletonAutoService, IDisposable
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
        /// Tries to register a protocol. Fails it the name is invalid or if it is the <see cref="MessageProtocol.ZeroProtocolName"/>.
        /// </summary>
        /// <param name="monitor">Required monitor.</param>
        /// <param name="name">Base protocol name.</param>
        /// <param name="version">Protocol version.</param>
        /// <param name="registered">The unique registration.</param>
        /// <returns>True on success, false otherwise.</returns>
        public bool TryRegister( IActivityMonitor monitor, string name, ushort version, [NotNullWhen(true)]out MessageProtocol? registered )
        {
            Throw.CheckNotNullArgument( name );
            name = name.Trim();
            if( name.Length == 0 || name.Contains( '.' ) || name.Equals( MessageProtocol.ZeroProtocol.Name, StringComparison.OrdinalIgnoreCase ) )
            {
                monitor.Error( $"Unable to register invalid protocol name '{name}'." );
            }
            else
            {
                var fullName = FormatFullName( name, version );
                registered = _protocols.AddOrUpdate( fullName, new MessageProtocol( fullName, name, version, false ), ( n, exist ) => exist );
                return true;
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

        void IDisposable.Dispose()
        {
            // Ensures that in tests contexts when disposing a root ServiceProvider, the
            // pooled messages (currently only one) is released.
            foreach( var protocol in _protocols.Values )
            {
                protocol.MessageFactory.Dispose();
            }
        }
    }
}
