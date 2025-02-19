using CK.AppIdentity.KeyManagement;
using CK.Core;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer;

static partial class ZeroProtocol
{
    /// <summary>
    /// This version drives the whole "0 Protocol" version.
    /// </summary>
    public const ushort CurrentVersion = 0;

    // Discriminator byte is the first byte of the payload.
    // Negotiation discriminators:
    internal const byte DNegoRejectRemote = 0;
    internal const byte DNegoFinalFailureMessage = 1;
    internal const byte DNegoDowngradeProtocol = 2;
    internal const byte DNegoAcceptedProtocolsMessage = 3;
    internal const byte DNegoMissingProtocols = 4;
    internal const byte DNegoEvictionDisallowed = 5;
    internal const byte DNegoOffRemote = 6;
    internal const byte DNegoFinalSuccessMessage = 7;
    internal const byte DNegoRequiredEnlistUrl = 8;
    // Run discriminators:
    internal const byte DRunGoodbye = 255;

    internal static readonly OutgoingMessageFactory _zeroFactory = MessageProtocol.ZeroProtocol.MessageFactory;

    /// <summary>
    /// Sends a <see cref="GoodbyeMessage"/> message. This is a signed message.
    /// </summary>
    /// <param name="transport">The transport.</param>
    /// <param name="message">The message.</param>
    /// <returns>True if the message has been sent, false if Transport has been canceled.</returns>
    public static async ValueTask<bool> SendGoodbyeMessageAsync( Transport transport, GoodbyeMessage message )
    {
        Throw.DebugAssert( transport.RemoteKeys != null );
        Throw.DebugAssert( message != null );
        using var m = CreateAndSignMessage( message,
                                            transport.RemoteKeys.Party.ApplicationIdentityService.SystemClock,
                                            transport.RemoteKeys.LocalKeys.CurrentIdentity );
        return await transport.SendAsync( 0, m ).ConfigureAwait( false );

        static IOutgoingMessage CreateAndSignMessage( GoodbyeMessage message, ISystemClock systemClock, LocalIdentityKey identity )
        {
            _zeroFactory.Create( sequence =>
            {
                var w = new FastByteWriter( sequence );
                w.WriteByte( DRunGoodbye );
                CreateAndWriteNonce( ref w, systemClock );
                GoodbyeMessage.WriteMessage( ref w, message );
                ComputeSHA512HashAndAppendSignature( ref w, identity );
            } );
            var builder = _zeroFactory.CreateBuilder();
            var sequence = builder.ObtainSequence();
            var w = new FastByteWriter( sequence );
            w.WriteByte( DRunGoodbye );
            CreateAndWriteNonce( ref w, systemClock );
            GoodbyeMessage.WriteMessage( ref w, message );
            ComputeSHA512HashAndAppendSignature( ref w, identity );
            return builder.CreateMessage( sequence );
        }
    }

    public static GoodbyeMessage? ReadGoodbyeMessage( IActivityLineEmitter logger, Transport transport, IncomingMessage message )
    {
        Throw.DebugAssert( transport.RemoteKeys?.TrustedIdentity != null );
        var r = new FastByteReader( message.Message );
        var discriminator = r.ReadByte();
        Throw.DebugAssert( discriminator == DRunGoodbye );
        var timedNonce = ReadNonce( ref r );
        var m = GoodbyeMessage.ReadMessage( ref r );

        if( !ComputeSHA512HashAndVerifySignature( ref r, transport.RemoteKeys.TrustedIdentity ) )
        {
            logger.Error( ActivityMonitor.Tags.ToBeInvestigated, $"Received unverifiable bye-bye message from '{transport.RemoteKeys.Party}': {m}" );
            return null;
        }
        if( !transport.RemoteKeys.CheckNonce( logger, in timedNonce ) )
        {
            return null;
        }
        return m;
    }

}
