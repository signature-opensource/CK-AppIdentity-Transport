using CK.AppIdentity.TransportLayer;
using CK.Core;

namespace CK.AppIdentity.BlobChannel
{
    public sealed class BlobChannelFeature : MessageProtocolFeature
    {
        readonly MessageProtocol[] _protocols;

        internal BlobChannelFeature( TransportFeature transport, MessageProtocolDirectoryService messageProtocolDirectory )
            : base( transport ) 
        {
            _protocols = new[] { messageProtocolDirectory.Register( "Blob" ) }; 
        }

        protected override IEnumerable<MessageProtocol> Protocols => _protocols;

    }

}
