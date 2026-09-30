-- SetupConfig: { "Requires": [ "CK.sMemberRemoveFromAllGroups" ] }
--
-- Destroys a PartyActor: automatically removes it from any Groups it may belong to.
--
create procedure CK.sPartyActorDestroy
(
    @ActorId int,
    @PartyActorId int
)
as
begin
    if @ActorId is null or @ActorId <= 0 throw 50000, 'Security.AnonymousNotAllowed', 1;
    if @PartyActorId is null or @PartyActorId <= 0 throw 50000, 'Argument.InvalidPartyActorId', 1;

    --[beginsp]

    if exists( select * from CK.tPartyActor where PartyActorId = @PartyActorId )
    begin
        --<PreDestroy revert />

        exec CK.sMemberRemoveFromAllGroups @ActorId, @PartyActorId;

        delete from CK.tActorProfile where ActorId = @PartyActorId;
        delete from CK.tPartyActor where PartyActorId = @PartyActorId;
        delete from CK.tActor where ActorId = @PartyActorId;

        --<PostDestroy />
    end

    --[endsp]
end
