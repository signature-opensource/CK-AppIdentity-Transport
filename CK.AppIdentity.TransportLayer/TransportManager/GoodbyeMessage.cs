using CK.Core;
using System;

namespace CK.AppIdentity.TransportLayer;

/// <summary>
/// Message sent from the party that is closing its connection.
/// See <see cref="GoodbyeKind"/>.
/// This message is signed.
/// </summary>
public abstract class GoodbyeMessage
{
    /// <summary>Maximal length of a remote end point description on the wire.</summary>
    public const int MaxEndPointDescriptionLength = 300;

    /// <summary>Maximal length of an instance id on the wire.</summary>
    public const int MaxInstanceIdLength = 64;

    /// <summary>
    /// Maximal length of a switch-off reason on the wire.
    /// <para>
    /// One constant for the writer, the reader and the check. Reading with a larger bound than the
    /// one the value is validated against accepts strings no correct sender can produce, and the
    /// discrepancy surfaces only as a Debug-only assert failing on someone else's machine.
    /// </para>
    /// </summary>
    public const int MaxReasonLength = 255;

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
            // CheckData, not DebugAssert: both of these arrive from the wire on the receiving side and
            // are surfaced to an operator afterwards. A DebugAssert is compiled out of Release, which
            // is precisely the build where a peer gets to choose them.
            Throw.CheckData( !string.IsNullOrWhiteSpace( remoteEndPointDescription )
                             && remoteEndPointDescription.Length <= MaxEndPointDescriptionLength
                             && remoteEndPointDescription.IsNormalized() );
            Throw.CheckData( !string.IsNullOrWhiteSpace( instanceId )
                             && instanceId.Length <= MaxInstanceIdLength
                             && Base64UrlHelper.IsBase64UrlCharacters( instanceId ) );
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
            return new Evicted( r.ReadString( MaxEndPointDescriptionLength ), r.ReadString( MaxInstanceIdLength ) );
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
            Throw.CheckData( reason.IsNormalized()
                             && reason.Length <= MaxReasonLength
                             && expectedAvailableTime?.Kind is null or DateTimeKind.Utc );
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
            // The constructor validates: one place, both directions.
            return new SwitchedOff( true, r.ReadString( MaxReasonLength ), r.ReadNullableDateTime() );
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
