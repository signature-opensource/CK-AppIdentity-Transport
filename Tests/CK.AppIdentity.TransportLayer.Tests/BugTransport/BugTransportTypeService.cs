using CK.AppIdentity.KeyManagement;
using CK.Core;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace CK.AppIdentity.TransportLayer.Tests;


public class BugTransportTypeService : TransportTypeService
{
    [Flags]
    public enum BugType
    {
        /// <summary>
        /// Throws in ParseAddress.
        /// </summary>
        ParseAddress = 1,

        /// <summary>
        /// Throws in TryCreateListener.
        /// </summary>
        ListenerCreate = 1 << 1,

        /// <summary>
        /// Throws in TryConnectAsync.
        /// </summary>
        TransportCreate = 1 << 2,

        /// <summary>
        /// Throws in TryConnectAsync (direct call error).
        /// </summary>
        TransportCreateInline = 1 << 3,

        /// <summary>
        /// TryConnectAsync returns a null.
        /// </summary>
        TransportCreateNull = 1 << 4,

        /// <summary>
        /// Throws in Transport.SendAsync.
        /// </summary>
        TransportWrite = 1 << 5,
        /// <summary>
        /// Throws in Transport.SendAsync (direct call error).
        /// </summary>
        TransportWriteInline = 1 << 6,

        /// <summary>
        /// Throws in Transport.ReceiveAsync.
        /// </summary>
        TransportRead = 1 << 7,
        /// <summary>
        /// Throws in Transport.ReceiveAsync (direct call error).
        /// </summary>
        TransportReadInline = 1 << 8,

        /// <summary>
        /// Throws in listener.DisposeAsync.
        /// </summary>
        DisposeListener = 1 << 9,
        /// <summary>
        /// Throws listener.DisposeAsync (direct call error).
        /// </summary>
        DisposeListenerInline = 1 << 10,


        DisposeTransport = 1 << 11,
        DisposeTransportInline = 1 << 12,
    }

    public BugTransportTypeService()
        : base( "bug" )
    {
    }

    public override TransportTypeAddress? ParseAddress( IActivityMonitor monitor, ReadOnlySpan<char> typed, ImmutableConfigurationSection section )
    {
        if( !Enum.TryParse<BugType>( typed, ignoreCase:true, out var type ) )
        {
            monitor.Error( $"Invalid '{section.Path}' = '{typed}'. It must be a BugType: ParseAddress, ListenerCreate, TransportCreate, TransportWrite, TransportRead." );
            return null;
        }
        if( (type & BugType.ParseAddress) != 0 )
        {
            throw new Exception( "Bug: ParseAddress." );
        }

        return new TransportTypeAddress( this, section, type );
    }

    protected override async Task<Transport?> TryConnectAsync( IParallelLogger logger, TransportTypeAddress typedAddress, IRemoteKeys remoteKeys, CancellationToken cancellation )
    {
        var type = (BugType)typedAddress.TypedAddress;
        if( (type & BugType.TransportCreateInline) != 0 )
        {
            throw new Exception( "Bug: TransportCreateInline." );
        }
        await Task.Delay( 20, cancellation ).ConfigureAwait( false );
        if( (type & BugType.TransportCreate) != 0 )
        {
            throw new Exception( "Bug: TransportCreate." );
        }
        if( (type & BugType.TransportCreateNull) != 0 )
        {
            return null;
        }
        return new BugTransport( typedAddress, remoteKeys );
    }

    protected override TransportListener? TryCreateListener( IActivityMonitor monitor, object opaqueHandle, object typedAddress )
    {
        var type = (BugType)typedAddress;
        if( (type & BugType.ListenerCreate) != 0 )
        {
            throw new Exception( "Bug: ListenerCreate." );
        }
        return new BugTransportListener( this, opaqueHandle, type );
    }
}
