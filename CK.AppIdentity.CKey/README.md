# CK.AppIdentity.CKey

**CKey is the local, low-level user interface of the AppIdentity store of a running party:** its checkpoint, its peering
issues, the approval of a remote with its code, the export and the import of the trust of a party. It acts on the party
itself, below the application commands, and it is reachable only on the machine of the party, by the OS user that runs
it.

It answers what the network can't: a party that waits for an approval and is connected to nothing, a deployment without
an approval page, the checkpoint of a party to write in the `TrustAnchors` of another one (see
[CK.AppIdentity.KeyManagement](../CK.AppIdentity.KeyManagement/README.md)).

## The "CKey" feature

[`CKeyFeatureDriver`](CKeyFeatureDriver.cs) is an opt-in feature of the application:

```json
"CK-AppIdentity": {
  "Local": { "AllowFeatures": "CKey" }
}
```

- **"Local" only:** a tenant domain that allows it fails the setup. The application's pipe gives access to its tenant
  domains.
- **One named pipe per process** ([`CKeyPipeServer`](CKeyPipeServer.cs)): `CKey_` followed by the first 16 hexadecimal
  digits of the SHA-256 of the application's full name (`CKeyPipeServer.GetPipeName`). When the name is taken (the same
  application started twice), CKey is not available in the second process (an error is logged).
- **Only the OS user of the party can connect.** On Windows, the pipe's security grants the current user and denies the
  network clients (a Windows named pipe can otherwise be reached from another machine). Elsewhere, the pipe is a Unix
  domain socket restricted to the current user (`PipeOptions.CurrentUserOnly`). The tool connects with
  `CurrentUserOnly`: a pipe created by another OS user is refused.
- **The protocol:** one request per connection, a UTF-8 JSON object prefixed by its length (4 bytes, little-endian),
  answered the same way (`"ok": true` and the result, or `"ok": false` and an `"error"`). The operations: `names`,
  `status`, `approve`, `export`, `import` (see [`CKeyOperations`](CKeyOperations.cs)). Each one is logged
  `SecurityCritical` with the OS user and the client's process (stated by the tool).

There is no other barrier than the OS user: whoever runs as the OS user of the party can already read its store and its
key store, and change its configuration. CKey gives nothing more than that.

## The ckey tool

The package ships the `ckey` tool: a framework-dependent executable that needs only the .NET runtime (never the SDK),
with no dependency beyond the base libraries. Its files are copied into the output and the publish folder of every
executable project that references the package (the host of a party): `ckey.dll` and its launchers, `ckey.cmd` on
Windows and `ckey` elsewhere (a shell script: NuGet doesn't keep the executable bit, so run `sh ckey`, or
`dotnet ckey.dll`).

```
ckey list
ckey status [--party <full name>]
ckey approve <remote> <code> [--party <full name>]
ckey export trust [<file>] [--party <full name>] [--expires <duration>] [--pwd <password>]
ckey import trust <file> [--party <full name>] [--pwd <password>]
```

- **The party:** by default, the application that runs from the folder of this `ckey` (the copy next to its host).
  `--party` names any local party of the OS user (an application or one of its tenant domains); it is required when no
  party, or several, run from that folder: `ckey` never picks one. This is a convenience, not a barrier.
- **`list`** finds the CKey pipes (`\\.\pipe\` on Windows, the `CoreFxPipe_` sockets of the temporary folder elsewhere)
  and asks each one its full names, its folder and its process.
- **`status`** shows the checkpoint of the party (`{seq}:{digest}`, ready for the `TrustAnchors` of another party) and
  its peering issues: the remote, the kind, the approval code, the key fingerprint, the enlistment URL and whether it is
  authenticated.
- **`approve`** approves the key that a remote presented with the approval code shown on the remote
  (`PeeringIssue.TryApprove`): the waiting side of a `RequiresBothApproval` without the anchor of an Authentication
  Center.
- **`export trust`** writes the trust of the party, the last events of its key event log (public data), to a file
  encrypted with AES-GCM under a key derived from a password (PBKDF2-SHA256): opaque without the password, any change
  (or a wrong password) fails the import. The password is generated (100 bits, printed once, to give by another channel
  than the file) unless `--pwd` gives it (scripts). The file expires: `--expires` takes `30m`, `2h`, `1d`... (1 hour by
  default, 7 days at most); the expiry is inside the encrypted data.
- **`import trust`** decrypts a trust file (the password is asked, not echoed, unless `--pwd` gives it; without a
  console and without `--pwd` the import fails), checks its expiry (with a margin of 5 minutes for the clocks), and pins
  the remote: it must be a configured remote of the party, not anchored (its trust anchor is the authority), not
  revoked; its key event log must verify. An export one way and an import the other give a "both approval" without an
  approval page nor codes.

The exit code is 0 on success, 1 on an error, 2 on a usage error.
