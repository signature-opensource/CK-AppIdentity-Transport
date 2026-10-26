# CK.AppIdentity.BlobChannel

A channel of [CK.AppIdentity.TransportLayer](../CK.AppIdentity.TransportLayer/README.md) that carries opaque `byte[]`
between two parties. It is more a worked example of a channel than a useful one, and the shortest path to seeing how a
protocol plugs into the transport layer: a driver, a feature and a protocol handler, in three short files.

## Activation

The "BlobChannel" feature is opt-in: the `"AllowFeatures"` of the remote must contain "BlobChannel" (see the
[CK.AppIdentity features](https://github.com/signature-opensource/CK-AppIdentity/blob/stable/CK.AppIdentity/Features/README.md)).
[`BlobChannelFeatureDriver`](BlobChannelFeatureDriver.cs) then adds a [`BlobChannelFeature`](BlobChannelFeature.cs) to
every such remote that has a `TransportFeature`. Its protocol is "Blob", in version 0: the name comes from the feature name
"BlobChannel", itself derived from the driver's type name.

## Use

```csharp
var blob = remote.GetRequiredFeature<BlobChannelFeature>();
blob.Received.Sync += ( monitor, channel, data ) => monitor.Info( $"Received {data.Length} bytes." );
bool queued = blob.TrySend( new byte[] { 1, 2, 3 } );
```

- `TrySend( data )` and `TrySendAsync( data, token )` queue the bytes for the remote. They return false when there is no
  connection to the remote yet (or any more), and when the send queue is full (`TrySendAsync` waits for room instead).
  The array is referenced by the message, not copied: it must not be changed once sent.
- `Received` is raised with a copy of each payload received from the remote.

## How it is built

- The driver specializes `ChannelFeatureDriver<BlobChannelFeature>` and creates the channel in `TryCreateChannel`.
- The feature specializes `ChannelFeature`: `CreateHandler` creates the protocol handler of the negotiated version, and
  the feature sends through its `CurrentHandler`, which exists only while the remote is connected.
- The handler ([`BlobChannelFeature.Protocol`](BlobChannelFeature.Protocol.cs)) specializes `PeerProtocolHandler`: it
  builds an outgoing message by adding the array as a segment of the message's sequence (no copy), and its `ReceiveAsync`
  copies the payload, disposes the message and raises `Received`.
