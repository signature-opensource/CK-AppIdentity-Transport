# Initial negotiation

## Exchanges

Initiator


Prefix ("CK-AppId“ in ASCII)
ZeroProtocolVersion (byte)
CoreApplicationIdentity.InstanceId (string)
FullName (string)
Protocols: count (byte) + protocol full names.
Nonce (ulong)
SystemClock.UtcNow
Identity keys and signatures

