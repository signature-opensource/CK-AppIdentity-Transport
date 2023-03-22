using CK.Core;

namespace CK.AppIdentity.TransportLayer
{
    sealed class InitialMessage : IUnknownRemote
    {
        readonly string _fullName;
        readonly string _endPointDescription;

        /// <summary>
        /// Outgoing message constructor. 
        /// </summary>
        /// <param name="p">The remote party.</param>
        public InitialMessage( IRemoteParty p )
        {
            _fullName = p.FullName;
            _endPointDescription = string.Empty;
        }

        /// <summary>
        /// Incoming message constructor: the end point that received it must provide its
        /// description (<see cref="IListener.EndPointDescription"/>).
        /// </summary>
        /// <param name="endPointDescription">The endpoint description.</param>
        /// <param name="m">The initial transport message.</param>
        public InitialMessage( string endPointDescription, TransportMessage m )
        {
            _endPointDescription = endPointDescription;
            var r = new FastByteReader( m.Message );
            _fullName = r.ReadString( CoreApplicationIdentity.FullNameMaxLength );
        }

        public void Write( ref FastByteWriter w )
        {
            w.WriteString( _fullName );
        }

        /// <summary>
        /// Gets the endpoint description. Empty string for the outgoing message.
        /// </summary>
        public string EndPointDescription => _endPointDescription;

        public string FullName => _fullName;
    }
}
