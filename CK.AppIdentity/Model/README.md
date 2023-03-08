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









## Mutable and immutable IConfigurationSection helpers.

A [ImmutableConfigurationSection](ImmutableConfigurationSection.cs) is a [IConfigurationSection](https://learn.microsoft.com/fr-fr/dotnet/api/microsoft.extensions.configuration.iconfigurationsection)
that captures once for all the content and path of any other `IConfigurationSection`.

Each application identity objects (`IApplicationIdentity`, `ILocalParty` and `IRemoteParty`) are bound to an immutable configuration.

The [MutableConfigurationSection](MutableConfigurationSection.cs) acts as a builder for immutable configuration and hence is used to
initialize dynamic `IRemoteParty` (including the optional `IRootRemoteParty.DomainApplicationIdentity`).

