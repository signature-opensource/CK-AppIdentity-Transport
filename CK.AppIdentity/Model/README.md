# Application identity model

This model captures the application identity and the other applications it interacts with. Its goal is to be
the single central point of configuration for an application (called a Party) and its peers (its Remote Parties)
and to "carry" all the communication and interaction services with its parties:
- It is as simple as possible to configure.
- Once initially configured, no configuration change is possible during the execution **for what has been configured**.
- Dynamic remote parties must be supported (these are the non initially configured beasts). These dynamic remotes must 
  be reconfigurable with a minimal impact on the running application (the application identity objects must be stable:
  reconfiguration must occur in place and in a thread safe manner).

An application identity is a triple: DomainName, EnvironementName, PartyName that are strictly defined as ASCII
identifiers (must only contain 'A'-'Z', 'a'-'z', '0'-'9' and '\_' characters and must not start with a digit nor a '\_'.). This triple
must be considered as a "path": "DomainName/EnvironementName/PartyName":
- Domain: is the name of an organization, a tenant (a customer name). The default DomainName (when nothing is configured) is "Default".
- Environment: is a deployment type identifier. Typical environment names are "Development", "Staging", "Production". This defaults to the 
  .Net [`IHostEnvironment.EnvironmentName`](https://learn.microsoft.com/fr-fr/dotnet/api/microsoft.extensions.hosting.ihostenvironment).
- Party: The application name is the application's logical name in its Domain and Environment. It defaults to the `IHostEnvironment.ApplicationName`.

One should be able to understand the interactions of any party by looking at its Application Identity configuration:
```json
{
	"DomainName": "LaToulousaine",
	"EnvironmentName": "Production",
	"Local": {
		"Name": "Trolley1"
	},
	"Remotes": [
  {
		"Name": "LogTower",
		"Address": "148.54.11.18:3712"
	},
  {
		"Name": "SignatureBox",
		"Address": "155.88.22.22"
	}]
}
```
There should be no more than that: Trolley1 sends its logs to a LogTower and can initiate communications with
the SignatureBox.

The SignatureBox also sends its logs to the same LogTower and knows the Trolley1 but also the Trolley2 and the MeasureStation.
```json
{
	"DomainName": "LaToulousaine",
	"EnvironmentName": "Production",
	"Local": {
		"Name": "SignatureBox"
	},
	"Remotes": [
  {
		"Name": "LogTower",
		"Address": "148.54.11.18:3712"
	},
  {
		"Name": "Trolley1"
	},
  {
		"Name": "Trolley2"
	},
  {
		"Name": "MeasureStation"
	}]
}
```
These 3 remotes have no Addresses: "LaToulousaine/Production/SignatureBox" is a server for these remotes and this is enough
for the warehouse with the SignatureBox, 2 trolleys and one measure station to work together.

Now we want the SignatureBox to interact with a OneCS application (the supervision and operation portal).
The OneCS application typically lives in the cloud. If the SignatureBox can be reached from the outside,
we just need to declare the new OneCS remote on the SignatureBox.

_Notes:_
- From now on, we don't show the LogTower configuration. This is the same for every party
  (if we want to target the same LogTower).
- We also don’t specify the EnvironementName anymore. This defaults to the IHostEnvironment.EnvironementName
  (that defaults to "Development")

The name of this new Party is the same as the DomainName: the "LaToulousaine" Party is the "domain controller" of
"LaToulousaine" Domain:
```json
{
	"DomainName": "LaToulousaine",
	"Local": {
		"Name": "SignatureBox"
	},
	"Remotes": [
  {
		"Name": "Trolley1"
	},
  {
		"Name": "Trolley2"
	},
  {
		"Name": "MeasureStation"
	},
  {
		"Name": "LaToulousaine"
	}]
}
```
Below is the OneCS configuration:
```json
{
	"DomainName": "LaToulousaine",
	"EnvironmentName": "Production",
	"Local": {
		"Name": "LaToulousaine"
	},
	"Remotes": [
  {
		"Name": "SignatureBox",
		"Address": "65.12.13.14"
	}]
}
```
If, for any reason, the SignatureBox cannot be reached from the outside (or if we prefer), then the configurations
become:
```json
{
	"DomainName": "LaToulousaine",
	"Local": {
		"Name": "LaToulousaine"
	},
	"Remotes": [
  {
		"Name": "SignatureBox"
	}]
}
```
And:
```json
{
	"DomainName": "LaToulousaine",
	"Local": {
		"Name": "SignatureBox"
	},
	"Remotes": [
  {
		"Name": "Trolley1"
	},
  {
		"Name": "Trolley2"
	},
  {
		"Name": "MeasureStation"
	},
  {
		"Name": "LaToulousaine",
		"Address": "27.28.29.30"
	}]
}
```










## Mutable and immutable IConfigurationSection helpers.

A [ImmutableConfigurationSection](ImmutableConfigurationSection.cs) is a [IConfigurationSection](https://learn.microsoft.com/fr-fr/dotnet/api/microsoft.extensions.configuration.iconfigurationsection)
that captures once for all the content and path of any other `IConfigurationSection`.

Each application identity objects (`IApplicationIdentity`, `ILocalParty` and `IRemoteParty`) are bound to an immutable configuration.

The [MutableConfigurationSection](MutableConfigurationSection.cs) acts as a builder for immutable configuration and hence is used to
initialize dynamic `IRemoteParty` (including the optional `IRootRemoteParty.DomainApplicationIdentity`).

