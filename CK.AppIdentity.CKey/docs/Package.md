CKey: the local, low-level user interface of the AppIdentity store of a running CK-AppIdentity party, through the
`ckey` tool shipped next to the host.

The opt-in "CKey" feature (`CKeyFeatureDriver`, declared by "Local:CKey": true) listens on one named pipe per process, reachable by the OS user of
the party only. The package ships the `ckey` tool (it needs only the .NET runtime), copied next to the host: `ckey list`,
`ckey status` (the checkpoint and the peering issues), `ckey approve` (a remote with its code), `ckey export trust` and
`ckey import trust` (the trust of a party in a file encrypted by a password, with an expiry).
