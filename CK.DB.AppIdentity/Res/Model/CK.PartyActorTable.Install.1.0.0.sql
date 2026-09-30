--[beginscript]

create table CK.tPartyActor
(
	PartyActorId int not null
	    constraint PK_CK_tPartyActor primary key nonclustered ( PartyActorId )
        constraint FK_CK_tPartyActor_PartyActorId foreign key references CK.tActor( ActorId ),

    -- This is the IParty.FullName ("Domain/$Party/#Environment"): its length is CoreApplicationIdentity.FullNameMaxLength
    -- and it only contains ASCII characters (hence the varchar).
    -- Collation is case insensitive (like tUser.UserName): in the CK-AppIdentity model, no two parties can differ only by case.
    FullName varchar( 192 ) collate Latin1_General_100_CI_AS not null constraint UK_CK_tPartyActor_FullName unique,

    -- Overall storage size for datetime2(0) is the same as for datetime2(2): 7 bytes.
    -- Let's keep the better precision for it.
    CreationDate datetime2 (2) not null constraint DF_CK_tPartyActor_CreationDate default ( sysutcdatetime() )
);

insert into CK.tPartyActor( PartyActorId, FullName ) values ( 0, '' );

--[endscript]
