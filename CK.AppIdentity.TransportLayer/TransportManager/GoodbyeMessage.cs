using CK.Core;
using System;

namespace CK.AppIdentity.TransportLayer
{
    /// <summary>
    /// Message sent from the party that is closing its connection.
    /// See <see cref="GoodbyeKind"/>.
    /// This message is signed.
    /// </summary>
    public abstract class GoodbyeMessage
    {
        GoodbyeKind _kind;

        GoodbyeMessage( GoodbyeKind kind ) => _kind = kind;

        /// <summary>
        /// Gets this message kind.
        /// </summary>
        public GoodbyeKind Kind => _kind;

        /// <summary>
        /// Gets whether this message comes from the remote or is issued by this side.
        /// </summary>
        public abstract bool IsFromRemote { get; }

        internal static void WriteMessage( ref FastByteWriter w, GoodbyeMessage message )
        {
            // Don't use the public enum Kind here.
            // We can freely add new discriminators for future versions
            // and continue to read back these ones.
            switch( message )
            {
                case Evicted m:
                    {
                        w.WriteByte( 0 );
                        m.Write( ref w );
                        break;
                    }
                case SwitchedOff m:
                    {
                        w.WriteByte( 1 );
                        m.Write( ref w );
                        break;
                    }
                case PartyDestroyed m:
                    {
                        w.WriteByte( 2 );
                        break;
                    }
                case ApplicationIdentityShutdown m:
                    {
                        w.WriteByte( 3 );
                        break;
                    }
            }
        }

        internal static GoodbyeMessage ReadMessage( ref FastByteReader r )
        {
            return r.ReadByte() switch
            {
                0 => Evicted.Read( ref r ),
                1 => SwitchedOff.Read( ref r ),
                2 => new PartyDestroyed( true ),
                3 => new ApplicationIdentityShutdown( true ),
                _ => Throw.InvalidDataException<GoodbyeMessage>(),
            };
        }

        /// <summary>
        /// An eviction message can be sent only by a listener and received by an initiator.
        /// <see cref="IsFromRemote"/> is always true.
        /// </summary>
        /// <param name="RemoteEndPointDescription">The newcomer endpoint description.</param>
        /// <param name="InstanceId">The newcomer <see cref="CoreApplicationIdentity.InstanceId"/>.</param>
        public sealed class Evicted : GoodbyeMessage
        {
            internal Evicted( string remoteEndPointDescription, string instanceId )
                : base( GoodbyeKind.Evicted )
            {
                Throw.DebugAssert( !string.IsNullOrWhiteSpace( remoteEndPointDescription ) && remoteEndPointDescription.Length <= 300 && remoteEndPointDescription.IsNormalized() );
                Throw.DebugAssert( !string.IsNullOrWhiteSpace( instanceId ) && instanceId.Length <= 64 && Base64UrlHelper.IsBase64UrlCharacters( instanceId ) );
                RemoteEndPointDescription = remoteEndPointDescription;
                InstanceId = instanceId;
            }

            /// <summary>
            /// Always true: no connection can be established.
            /// </summary>
            public override bool IsFromRemote => true;

            /// <summary>
            /// Gets the newcomer endpoint description.
            /// Length is between 1 and 255.
            /// </summary>
            public string RemoteEndPointDescription { get; }

            /// <summary>
            /// Gets the newcomer instance identifier.
            /// </summary>
            public string InstanceId { get; }

            /// <summary>
            /// Overridden to return "Remote: Evicted by 'instance identifier' at 'remote endpoint description'.".
            /// </summary>
            /// <returns>A readable string.</returns>
            public override string ToString() => $"Remote: Evicted by '{InstanceId}' at '{RemoteEndPointDescription}'.";

            internal void Write( ref FastByteWriter w )
            {
                w.WriteString( RemoteEndPointDescription );
                w.WriteString( InstanceId );
            }

            internal static Evicted Read( ref FastByteReader r )
            {
                return new Evicted( r.ReadString( 300 ), r.ReadString( 64 ) );
            }
        }

        /// <summary>
        /// A switched off message can be sent and received by listener and initiator.
        /// </summary>
        public sealed class SwitchedOff : GoodbyeMessage
        {
            internal SwitchedOff( bool isFromRemote, string reason, DateTime? expectedAvailableTime )
                : base( GoodbyeKind.SwitchedOff )
            {
                Throw.DebugAssert( reason.IsNormalized() && reason.Length < 256 && expectedAvailableTime?.Kind is null or DateTimeKind.Utc );
                IsFromRemote = isFromRemote;
                Reason = reason;
                ExpectedAvailableTime = expectedAvailableTime;
            }

            /// <inheritdoc />
            public override bool IsFromRemote { get; }

            /// <summary>
            /// Gets an optional reason (can be empty).
            /// </summary>
            public string Reason { get; }

            /// <summary>
            /// Gets the the expected instant where .
            /// </summary>
            public DateTime? ExpectedAvailableTime { get; }

            /// <summary>
            /// Overridden to return the reason.
            /// </summary>
            /// <returns>A readable string.</returns>
            public override string ToString() => $"{(IsFromRemote ? "Remote: " : "")}Switched off, Reason: '{Reason}'.";

            internal void Write( ref FastByteWriter w )
            {
                w.WriteString( Reason );
                w.WriteNullableDateTime( ExpectedAvailableTime );
            }

            internal static SwitchedOff Read( ref FastByteReader r )
            {
                var reason = r.ReadString( 300 );
                var at = r.ReadNullableDateTime();
                Throw.CheckData( reason.IsNormalized() && at?.Kind is null or DateTimeKind.Utc );
                return new SwitchedOff( true, reason, at );
            }
        }

        /// <summary>
        /// A switched off message can be sent and received by listener and initiator.
        /// </summary>
        public sealed class PartyDestroyed : GoodbyeMessage
        {
            internal PartyDestroyed( bool isFromRemote )
                : base( GoodbyeKind.PartyDestroyed ) 
            {
                IsFromRemote = isFromRemote;
            }

            /// <inheritdoc />
            public override bool IsFromRemote { get; }

            /// <summary>
            /// Overridden to return "Destroyed Party.".
            /// </summary>
            /// <returns>A readable string.</returns>
            public override string ToString() => $"{(IsFromRemote ? "Remote: " : "")}Destroyed Party.";
        }

        /// <summary>
        /// A <see cref="GoodbyeKind.ApplicationIdentityShutdown"/> message can be sent and received
        /// by listener and initiator.
        /// </summary>
        public sealed class ApplicationIdentityShutdown : GoodbyeMessage
        {
            internal ApplicationIdentityShutdown( bool isFromRemote )
                : base( GoodbyeKind.ApplicationIdentityShutdown )
            {
                IsFromRemote = isFromRemote;
            }

            /// <inheritdoc />
            public override bool IsFromRemote { get; }

            /// <summary>
            /// Overridden to return "Shutdown ApplicationIdentityService.".
            /// </summary>
            /// <returns>A readable string.</returns>
            public override string ToString() => $"{(IsFromRemote?"Remote: ": "")}Shutdown ApplicationIdentityService.";
        }

    }
}
