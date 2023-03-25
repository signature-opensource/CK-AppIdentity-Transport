using CK.Core;
using System.Buffers;

namespace CK.AppIdentity.TransportLayer
{
    sealed class AcceptedRemoteReplyMessage
    {
        public AcceptedRemoteReplyMessage()
        {
        }

        public void Write( ref FastByteWriter w )
        {
        }
    }

    /// <summary>
    /// Immutable initial message that is a <see cref="IUnknownRemote"/>: by keeping
    /// this message we can discover new remotes that need to enter the system.
    /// </summary>
    sealed class InitialMessage : IUnknownRemote
    {
        /// <summary>
        /// This version drives the whole "0 Protocol" version.
        /// </summary>
        public const int CurrentVersion = 0;

        readonly string _fullName;
        readonly string _endPointDescription;
        private readonly int _version;

        /// <summary>
        /// Outgoing message constructor. 
        /// </summary>
        /// <param name="p">The remote party.</param>
        public InitialMessage( IRemoteParty p )
        {
            _fullName = p.FullName;
            _endPointDescription = string.Empty;
        }

        InitialMessage( ref FastByteReader r, string endPointDescription, int version )
        {
            _endPointDescription = endPointDescription;
            _version = version;
            _fullName = r.ReadString( CoreApplicationIdentity.FullNameMaxLength );
        }

        /// <summary>
        /// Incoming message parse: the end point that received it must provide its
        /// description (<see cref="IListener.EndPointDescription"/>).
        /// Null is returned if the version is greater than <see cref="CurrentVersion"/>.
        /// </summary>
        /// <param name="endPointDescription">The endpoint description.</param>
        /// <param name="m">The initial transport message or null if the version is greater than our version.</param>
        public static InitialMessage? Parse( string endPointDescription, TransportMessage m )
        {
            var r = new FastByteReader( m.Message );
            int version = checked( (int)r.ReadSmallUInt32() );
            if( version > InitialMessage.CurrentVersion ) return null;
            return new InitialMessage( ref r, endPointDescription, version );
        }


        public void Write( ref FastByteWriter w )
        {
            w.WriteSmallUInt32( CurrentVersion );
            w.WriteString( _fullName );
        }

        public int Version => _version;

        public string IncomingEndPointDescription => _endPointDescription;

        public string FullName => _fullName;
    }
}
