using CK.AppIdentity.TransportLayer;
using CK.Core;

namespace CK.AppIdentity.PocoChannel
{
    public class PocoChannelFeature : MessageProtocolFeature
    {
        readonly MessageProtocol[] _protocols;

        public PocoChannelFeature( TransportFeature transportFeature, MessageProtocolDirectoryService messageProtocolDirectory )
            : base( transportFeature )
        {
            _protocols = new[] { messageProtocolDirectory.Register( "Poco" ) };
        }

        protected override IEnumerable<MessageProtocol> Protocols => _protocols;

        protected override bool ValidateNegotiatedProtocols( IActivityLogger logger, IReadOnlyList<MessageProtocol> protocols )
        {
            if( !protocols.Contains( _protocols[0] ) )
            {
                logger.Error( $"Remote for '{Transport.Party.FullName}' must support the 'Poco' protocol." );
                return false;
            }
            return true;
        }
    }
}
