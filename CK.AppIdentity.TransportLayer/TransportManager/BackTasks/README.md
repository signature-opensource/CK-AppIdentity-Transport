# Initial negotiation

## Exchanges

Initiator


Prefix ("CK-AppId“ in ASCII)
ZeroProtocolVersion (byte)
CoreApplicationIdentity.InstanceId (string)
FullName (string)
Protocols: count (byte) + protocol full names.
Nonce (UInt64)
DateTime.UtcNow
Identity keys and signatures

