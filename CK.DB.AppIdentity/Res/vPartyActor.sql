create view CK.vPartyActor
as
    select pa.PartyActorId,
           pa.FullName,
           pa.CreationDate,
           DisplayName = pa.FullName
    from CK.tPartyActor pa;
