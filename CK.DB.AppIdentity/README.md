# CK.DB.AppIdentity

Implements the **PartyActor**: an Actor that represents a CK-AppIdentity party (an `IParty`).

A PartyActor is always system wide: it is not contained in any Zone. It is identified by its `FullName`, the
`IParty.FullName` (`"Domain/$Party/#Environment"`) used as-is. This name is unique and uses the Latin1_General_100_CI_AS collation
(like `tUser.UserName`): in the CK-AppIdentity model, no two parties can differ only by case. Since party names are
restricted to ASCII characters, the `FullName` is a `varchar( 192 )` (192 is `CoreApplicationIdentity.FullNameMaxLength`).

This package extends [CK-DB-Actor](https://github.com/signature-opensource/CK-DB/tree/stable/CK.DB.Actor) by introducing a new `CK.tPartyActor` table
and two stored procedures:
- `CK.sPartyActorEnsure` finds or creates the PartyActor for a `FullName` (concurrent calls are safe). The `FullName` is not checked:
  the caller is trusted to provide a valid party full name.
- `CK.sPartyActorDestroy` destroys a PartyActor (removing it from the Groups it belongs to).

A PartyActor can be added to Groups as any other Actor (see `CK.sGroupMemberAdd`).

The view `CK.vPartyActor` is mirroring all fields from the table `CK.tPartyActor`. It aims to be transformed by other packages.
This package transforms the `CK.vGroupMember` view to add the `PartyActor` member type.
