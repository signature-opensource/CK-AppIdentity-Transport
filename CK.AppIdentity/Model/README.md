# Application identity model

This model captures the application identity and the other applications it interacts with. Its goal is to be
the single central point of configuration for an application (called a Party) and its peers (its Parties)
and to "carry" all the communication and interaction services with its parties:
- It is as simple as possible to configure.
- Once initially configured, no configuration change is possible during the execution **for what has been configured**.
- Dynamic parties must be supported (these are the non initially configured beasts). These dynamic parties must 
  be reconfigurable with a minimal impact on the running application (the application identity objects must be stable:
  reconfiguration must occur in place and in a thread safe manner).

An application identity is a triple: DomainName, PartyName, EnvironementName that are strictly defined
(see CK.Core.CoreApplicationIdentity).

One should be able to understand the interactions of any party by looking at its Application Identity configuration:
```json
{
  "FullName": "LaToulousaine/$Trolley1/#Production",
  "Parties": [
   {
     "PartyName": "$LogTower",
     "Address": "148.54.11.18:3712"
   },
   {
     "PartyName": "$SignatureBox",
     "Address": "155.88.22.22"
   }]
}
```
There should be no more than that: Trolley1 sends its logs to a LogTower and can initiate communications with
the SignatureBox.

The SignatureBox also sends its logs to the same LogTower and knows the Trolley1 but also the Trolley2 and the PickingStation.
```json
{
  "FullName": "LaToulousaine/$SignatureBox/#Production",
  "Parties": [
  {
    "DomainName": "CentralLogwer",
    "PartyName": "LogTower",
    "Address": "148.54.11.18:3712"
  },
  {
    "PartyName": "Trolley1"
  },
  {
    "PartyName": "Trolley2"
  },
  {
    "PartyName": "PickingStation"
  }]
}
```
These 3 remotes have no Addresses: "LaToulousaine/$SignatureBox/#Production" is a server for these parties and this is enough
for the warehouse with the SignatureBox, 2 trolleys and one picking station to work together.

Now we want the SignatureBox to interact with a OneCS application (the supervision and operation portal).
The OneCS application typically lives in the cloud. If the SignatureBox can be reached from the outside,
we just need to declare the new OneCS remote on the SignatureBox.

_Notes:_
- From now on, we don't show the LogTower configuration. This is the same for every party
  (if we want to target the same LogTower).
- We also don’t specify the EnvironementName anymore. This defaults to the IHostEnvironment.EnvironementName
  (that defaults to "#Development")

The name of this new Party is the same as the DomainName: the "LaToulousaine/$LaToulousaine" Party is the "domain controller"
of "LaToulousaine" domain:
```json
{
  "FullName": "LaToulousaine/$SignatureBox",
  "Parties": [
  {
    "PartyName": "$Trolley1"
  },
  {
    "PartyName": "$Trolley2"
  },
  {
    "PartyName": "$PickingStation"
  },
  {
    "PartyName": "$LaToulousaine"
  }]
}
```
Below is the OneCS configuration:
```json
{
  "FullName": "LaToulousaine/$LaToulousaine"
  "Parties": [
  {
    "PartyName": "$SignatureBox",
    "Address": "65.12.13.14"
  }]
}
```
If, for any reason, the SignatureBox cannot be reached from the outside (or if we prefer), then the configurations
become:
```json
{
  "FullName": "LaToulousaine/$LaToulousaine"
  "Parties": [
  {
    "PartyName": "$SignatureBox",
  }]
}
```
And:
```json
{
  "FullName": "LaToulousaine/$SignatureBox",
  "Parties": [
  {
    "PartyName": "$Trolley1"
  },
  {
    "PartyName": "$Trolley2"
  },
  {
    "PartyName": "$PickingStation"
  },
  {
    "PartyName": "$LaToulousaine",
    "Address": "27.28.29.30:3712"
  }]
}
```


## Mutable and immutable IConfigurationSection helpers (from CK.Core).

A `ImmutableConfigurationSection` is a [IConfigurationSection](https://learn.microsoft.com/fr-fr/dotnet/api/microsoft.extensions.configuration.iconfigurationsection)
that captures once for all the content and path of any other `IConfigurationSection`.

Each application identity objects are bound to an immutable configuration.

The `MutableConfigurationSection` acts as a builder for immutable configuration and hence is used to
initialize dynamic parties.


