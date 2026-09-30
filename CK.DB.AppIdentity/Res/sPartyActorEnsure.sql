-- SetupConfig: { "Requires": [ "CK.sActorCreate" ] }
--
-- Finds or creates the PartyActor identified by its FullName.
-- The FullName is not checked (it must be a valid IParty.FullName), except that it cannot be empty:
-- the empty FullName is the one of the PartyActor 0.
--
create procedure CK.sPartyActorEnsure
(
    @ActorId int,
    @FullName varchar( 192 ),
    @PartyActorIdResult int output
)
as
begin
    if @ActorId is null or @ActorId <= 0 throw 50000, 'Security.AnonymousNotAllowed', 1;
    if @FullName is null or @FullName = '' throw 50000, 'Argument.InvalidPartyActorFullName', 1;

    --[beginsp]

    -- The range lock (updlock, serializable) is held until the end of the transaction:
    -- concurrent ensures of the same new FullName are serialized instead of failing on the unique key.
    set @PartyActorIdResult = null;
    select @PartyActorIdResult = PartyActorId
        from CK.tPartyActor with( updlock, serializable )
        where FullName = @FullName;

    if @PartyActorIdResult is null
    begin
        --<PreCreate revert />

        exec CK.sActorCreate @ActorId, @PartyActorIdResult output;
        insert into CK.tPartyActor( PartyActorId, FullName ) values ( @PartyActorIdResult, @FullName );

        --<PostCreate />
    end

    --[endsp]
end
