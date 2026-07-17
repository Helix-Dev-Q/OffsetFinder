#include "pch.h"

#include "../Public/Generator.h"
#include "../Public/Finder.h"
#include "../Public/RedirectFinder.h"

#include <cmath>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace
{
    uint64_t Rel(uint64_t Absolute)
    {
        if (!Absolute || Absolute < ImageBase)
            return 0;
        return Absolute - ImageBase;
    }

    uint64_t FindGWorld()
    {
        const char* Patterns[] = {
            "48 8B 1D ? ? ? ? 48 85 DB 74 3B 41 B0 01",
            "48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ? 48 85 C9 74 ? 48 8B 49",
            "48 89 05 ? ? ? ? 48 8B 4B ? E8",
            "48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ? 48 85 C9 74 06 48 8B 49 70",
            "48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ? 48 85 C9 74 ? E8",
        };

        for (auto Pattern : Patterns)
        {
            auto Scanner = Memcury::Scanner::FindPattern(Pattern);
            if (!Scanner.Get())
                continue;

            auto Addr = Scanner.RelativeOffset(3).Get();
            if (Addr && Addr > ImageBase)
                return Addr;
        }

        auto SRef = Memcury::Scanner::FindStringRef(L"UWorld::CleanupWorld", false);
        if (SRef.Get())
        {
            for (int i = 0; i < 0x200; i++)
            {
                auto Ptr = (uint8_t*)(SRef.Get() - i);
                if (*Ptr == 0x48 && *(Ptr + 1) == 0x8B && (*(Ptr + 2) == 0x05 || *(Ptr + 2) == 0x0D || *(Ptr + 2) == 0x1D))
                    return Memcury::Scanner(Ptr).RelativeOffset(3).Get();
            }
        }

        return 0;
    }

    uint64_t FindGEngine()
    {
        const char* Patterns[] = {
            "48 8B 0D ? ? ? ? 48 85 C9 74 ? E8 ? ? ? ? 48 8B 0D",
            "48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ? 48 85 C9 74 ? 48 8B 49 70",
            "48 8B 0D ? ? ? ? 48 8B D8 48 85 C9 0F 84",
        };

        for (auto Pattern : Patterns)
        {
            auto Scanner = Memcury::Scanner::FindPattern(Pattern);
            if (Scanner.Get())
            {
                auto Addr = Scanner.RelativeOffset(3).Get();
                if (Addr && Addr > ImageBase)
                    return Addr;
            }
        }

        return 0;
    }

    std::string FormatVersion(double Version)
    {
        std::ostringstream Oss;
        Oss << std::fixed;

        double Trunc = std::floor(Version * 100.0 + 0.5) / 100.0;
        if (std::fabs(Trunc - std::floor(Trunc)) < 0.001)
            Oss << std::setprecision(0) << Trunc;
        else if (std::fabs(Trunc * 10.0 - std::floor(Trunc * 10.0 + 0.5)) < 0.001)
            Oss << std::setprecision(1) << Trunc;
        else
            Oss << std::setprecision(2) << Trunc;

        return Oss.str();
    }

    void EmitRva(std::ostringstream& Out, const char* Name, uint64_t Absolute)
    {
        Out << "\t\t\t" << Name << " = ImageBase + 0x" << std::uppercase << std::hex << Rel(Absolute) << std::dec << ";\n";
    }

    void EmitVft(std::ostringstream& Out, const char* Name, uint32_t Index)
    {
        Out << "\t\t\t" << Name << " = 0x" << std::uppercase << std::hex << Index << std::dec << ";\n";
    }

    void EmitDecl(std::ostringstream& Out, const char* Name, bool IsVft)
    {
        if (IsVft)
            Out << "\t\tstatic inline uint32_t " << Name << ";\n";
        else
            Out << "\t\tstatic inline uint64_t " << Name << ";\n";
    }

    void CopyToClipboard(const std::string& Text)
    {
        if (!OpenClipboard(nullptr))
            return;

        EmptyClipboard();
        HGLOBAL Mem = GlobalAlloc(GMEM_MOVEABLE, Text.size() + 1);
        if (Mem)
        {
            memcpy(GlobalLock(Mem), Text.c_str(), Text.size() + 1);
            GlobalUnlock(Mem);
            SetClipboardData(CF_TEXT, Mem);
        }
        CloseClipboard();
    }
}

std::string OffsetFinder::GenerateGameserverOffsets(const std::wstring& OutputPath)
{
    printf("initing sdk...\n");
    SDK::Init();

    const double FnVersion = VersionInfo.FortniteVersion;
    const double EngineVersion = VersionInfo.EngineVersion;

    if (FnVersion < 1.72 || FnVersion > 30.00)
    {
        printf("uh, got fn %.2f (ue %.2f) - this is meant for 1.7.2 to 30.00, might be flaky\n", FnVersion, EngineVersion);
    }
    else
    {
        printf("fn %.2f / ue %.2f\n", FnVersion, EngineVersion);
    }

    printf("scanning...\n");

    const uint64_t GWorld = FindGWorld();
    const uint64_t GEngine = FindGEngine();
    const uint64_t GUObjectArray = Offsets::GObjectsChunked ? Offsets::GObjectsChunked : Offsets::GObjectsUnchunked;
    const uint64_t GIsClient = FindGIsClient();
    const uint64_t GIsServer = FindGIsServer();

    struct NamedAddr
    {
        const char* Name;
        uint64_t Value;
        bool IsVft;
    };

    std::vector<NamedAddr> Entries = {
        { "GWorld", GWorld, false },
        { "GEngine", GEngine, false },
        { "GUObjectArray", GUObjectArray, false },
        { "GIsClient", GIsClient, false },
        { "GIsServer", GIsServer, false },
        { "Realloc", Offsets::Realloc, false },
        { "AppendString", Offsets::AppendString, false },
        { "ToString", Offsets::ToString, false },
        { "Step", Offsets::Step, false },
        { "StepExplicitProperty", Offsets::StepExplicitProperty, false },
        { "GetInterfaceAddress", Offsets::GetInterfaceAddress, false },
        { "StaticFindObject", Offsets::StaticFindObject, false },
        { "StaticLoadObject", Offsets::StaticLoadObject, false },
        { "FNameCtor", Offsets::FNameConstructor, false },
        { "SpawnActorTransform", Offsets::SpawnActor, false },
        { "ProcessEventVft", Offsets::ProcessEventVft, true },
        { "WorldNetMode", FindGetNetMode(), false },
        { "GetWorldContext", FindGetWorldContext(), false },
        { "CreateNetDriver", FindCreateNetDriver(), false },
        { "CreateNetDriverWorldContext", FindCreateNetDriverWorldContext(), false },
        { "InitListen", FindInitListen(), false },
        { "SetWorld", FindSetWorld(), false },
        { "TickFlush", FindTickFlush(), false },
        { "ServerReplicateActors", FindServerReplicateActors(), false },
        { "DispatchRequest", FindSendRequestNow(), false },
        { "GetMaxTickRate", FindGetMaxTickRate(), false },
        { "GiveAbility", FindGiveAbility(), false },
        { "ConstructAbilitySpec", FindConstructAbilitySpec(), false },
        { "InternalTryActivateAbility", FindInternalTryActivateAbility(), false },
        { "GiveAbilityAndActivateOnce", FindGiveAbilityAndActivateOnce(), false },
        { "ClearAbility", FindClearAbility(), false },
        { "ApplyCharacterCustomization", FindApplyCharacterCustomization(), false },
        { "SetupSafeZonePhase", FindHandlePostSafeZonePhaseChanged(), false },
        { "SpawnLoot", FindSpawnLoot(), false },
        { "FinishedTargetSpline", FindFinishedTargetSpline(), false },
        { "PickTeam", FindPickTeam(), false },
        { "CantBuild", FindCantBuild(), false },
        { "ReplaceBuildingActor", FindReplaceBuildingActor(), false },
        { "KickPlayer", FindKickPlayer(), false },
        { "EncryptionPatch", FindEncryptionPatch(), false },
        { "GameSessionPatch", FindGameSessionPatch(), false },
        { "RemoveInventoryItem", FindRemoveInventoryItem(), false },
        { "RemoveInventoryStateValue", FindRemoveInventoryStateValue(), false },
        { "SetInventoryStateValue", FindSetInventoryStateValue(), false },
        { "HandleZiplineStateChanged", FindOnRep_ZiplineState(), false },
        { "RemoveFromAlivePlayers", FindRemoveFromAlivePlayers(), false },
        { "StartAircraftPhase", FindStartAircraftPhase(), false },
        { "SetPickupItems", FindSetPickupItems(), false },
        { "CallPreReplication", FindCallPreReplication(), false },
        { "SendClientAdjustment", FindSendClientAdjustment(), false },
        { "SetChannelActor", FindSetChannelActor(), false },
        { "SetChannelActorForDestroy", FindSetChannelActorForDestroy(), false },
        { "CreateChannel", FindCreateChannel(), false },
        { "ReplicateActor", FindReplicateActor(), false },
        { "CloseActorChannel", FindCloseActorChannel(), false },
        { "ClientHasInitializedLevelFor", FindClientHasInitializedLevelFor(), false },
        { "StartBecomingDormant", FindStartBecomingDormant(), false },
        { "FlushDormancy", FindFlushDormancy(), false },
        { "SendDestructionInfo", FindSendDestructionInfo(), false },
        { "EnterAircraft", FindEnterAircraft(), false },
        { "GetPlayerViewPoint", FindGetPlayerViewPoint(), false },
        { "GetNamePool", FindGetNamePool(), false },
        { "IsNetReady", FindIsNetReady(), false },
        { "SpawnInitialSafeZone", FindSpawnInitialSafeZone(), false },
        { "UpdateSafeZonesPhase", FindUpdateSafeZonesPhase(), false },
        { "UpdateIrisReplicationViews", FindUpdateIrisReplicationViews(), false },
        { "PreSendUpdate", FindPreSendUpdate(), false },
        { "HandleMatchHasStarted", FindHandleMatchHasStarted(), false },
        { "InitializeBuildingActor", FindInitializeBuildingActor(), false },
        { "PostInitializeSpawnedBuildingActor", FindPostInitializeSpawnedBuildingActor(), false },
        { "InitializeFlightPath", FindInitializeFlightPath(), false },
        { "ControllerReset", FindReset(), false },
        { "NotifyGameMemberAdded", FindNotifyGameMemberAdded(), false },
        { "SetGamePhase", FindSetGamePhase(), false },
        { "PayBuildableClassPlacementCost", FindPayBuildableClassPlacementCost(), false },
        { "CanAffordToPlaceBuildableClass", FindCanAffordToPlaceBuildableClass(), false },
        { "CanPlaceBuildableClassInStructuralGrid", FindCanPlaceBuildableClassInStructuralGrid(), false },
        { "LoadPlayset", FindLoadPlayset(), false },
        { "SetState", FindSetState(), false },
        { "MinigameSettingsBuildingBeginPlay", FindMinigameSettingsBuilding__BeginPlay(), false },
        { "PickSupplyDropLocation", FindPickSupplyDropLocation(), false },
        { "SetPickupTarget", FindSetPickupTarget(), false },
        { "InitializePlayerGameplayAbilities", FindInitializePlayerGameplayAbilities(), false },
        { "Listen", FindListenCall(), false },
        { "QueueStatEvent", FindQueueStatEvent(), false },
        { "FinishWorldInitialization", FindFinishWorldInitialization(), false },
        { "SetIsDoorOpen", FindSetIsDoorOpen(), false },
        { "ActivatePhase", FindActivatePhase(), false },
        { "SelectAndSetupMyBuildingLevel", FindSelectAndSetupMyBuildingLevel(), false },
        { "IsNetRelevantForVft", (uint64_t)FindIsNetRelevantForVft(), true },
        { "OnItemInstanceAddedVft", FindOnItemInstanceAddedVft(), true },
        { "SpawnDecoVft", FindSpawnDecoVft(), true },
        { "ShouldAllowServerSpawnDecoVft", FindShouldAllowServerSpawnDecoVft(), true },
    };

    printf("grabbing ufuncs...\n");

    struct UFuncTarget
    {
        const char* ExecName; 
        const char* VftName;  
        const char* Classes[5];
        const char* Functions[4];
        bool UseImpl;
    };

    static const UFuncTarget UFuncTargets[] = {
        // GameMode
        { "ReadyToStartMatch", nullptr, { "FortGameModeAthena", "FortGameMode", "GameModeBase", nullptr }, { "ReadyToStartMatch", nullptr }, false },
        { "SpawnDefaultPawnFor", "SpawnDefaultPawnForVft", { "FortGameModeAthena", "FortGameMode", "GameMode", nullptr }, { "SpawnDefaultPawnFor", nullptr }, false },
        { "HandleStartingNewPlayer", "HandleStartingNewPlayerVft", { "FortGameModeAthena", "FortGameMode", "GameMode", nullptr }, { "HandleStartingNewPlayer", nullptr }, false },
        { "OnAircraftExitedDropZone", nullptr, { "FortGameModeAthena", nullptr }, { "OnAircraftExitedDropZone", nullptr }, false },
        { "GetPhaseInfo", nullptr, { "FortSafeZoneIndicator", nullptr }, { "GetPhaseInfo", nullptr }, false },

        // Building
        { "SetDynamicFoundationEnabled", nullptr, { "BuildingFoundation", nullptr }, { "SetDynamicFoundationEnabled", nullptr }, false },
        { "SetDynamicFoundationTransform", nullptr, { "BuildingFoundation", nullptr }, { "SetDynamicFoundationTransform", nullptr }, false },
        { "ServerSpawnDeco", "ServerSpawnDecoVft", { "FortDecoTool", "FortTrapTool", nullptr }, { "ServerSpawnDeco", "ServerSpawnDeco_Implementation", nullptr }, false },
        { "ServerCreateBuildingAndSpawnDeco", "CreateBuildingAndSpawnDecoInternalVft", { "FortDecoTool", "FortDecoTool_ContextTrap", nullptr }, { "ServerCreateBuildingAndSpawnDeco", "ServerCreateBuildingAndSpawnDeco_Implementation", nullptr }, false },

        // Creative / Mutators
        { "TeleportPlayerToLinkedVolume", nullptr, { "FortAthenaCreativePortal", nullptr }, { "TeleportPlayerToLinkedVolume", nullptr }, false },
        { "OnGamePhaseStepChanged", nullptr, { "FortAthenaMutator", nullptr }, { "OnGamePhaseStepChanged", nullptr }, false },
        { "OnGamePhaseChanged", nullptr, { "FortAthenaMutator", nullptr }, { "OnGamePhaseChanged", nullptr }, false },

        // Inventory / pickups
        { "SpawnPickup", nullptr, { "FortAthenaSupplyDrop", nullptr }, { "SpawnPickup", nullptr }, false },
        { "K2_SpawnPickupInWorld", nullptr, { "FortKismetLibrary", nullptr }, { "K2_SpawnPickupInWorld", nullptr }, false },
        { "K2_SpawnPickupInWorldWithClassAndItemEntry", nullptr, { "FortKismetLibrary", nullptr }, { "K2_SpawnPickupInWorldWithClassAndItemEntry", nullptr }, false },
        { "SpawnItemVariantPickupInWorld", nullptr, { "FortKismetLibrary", nullptr }, { "SpawnItemVariantPickupInWorld", nullptr }, false },
        { "PickLootDrops", nullptr, { "FortKismetLibrary", nullptr }, { "PickLootDrops", nullptr }, false },
        { "GiveItemToInventoryOwner", nullptr, { "FortKismetLibrary", nullptr }, { "GiveItemToInventoryOwner", nullptr }, false },
        { "K2_RemoveItemFromPlayer", nullptr, { "FortKismetLibrary", nullptr }, { "K2_RemoveItemFromPlayer", nullptr }, false },
        { "K2_RemoveItemFromPlayerByGuid", nullptr, { "FortKismetLibrary", nullptr }, { "K2_RemoveItemFromPlayerByGuid", nullptr }, false },
        { "OpenActor", nullptr, { "FortKismetLibrary", nullptr }, { "OpenActor", nullptr }, false },
        { "CloseActor", nullptr, { "FortKismetLibrary", nullptr }, { "CloseActor", nullptr }, false },
        { "TeleportPlayerPawn", nullptr, { "FortMissionLibrary", nullptr }, { "TeleportPlayerPawn", nullptr }, false },

        // Physics / vehicles
        { "ServerMove", nullptr, { "FortPhysicsPawn", "PhysicsPawn", nullptr }, { "ServerMove", nullptr }, false },
        { "ServerMoveReliable", nullptr, { "FortPhysicsPawn", "PhysicsPawn", nullptr }, { "ServerMoveReliable", nullptr }, false },
        { "ServerUpdatePhysicsParams", nullptr, { "FortPhysicsPawn", "FortAthenaVehicle", "PhysicsPawn", nullptr }, { "ServerUpdatePhysicsParams", nullptr }, false },
        { "ServerUpdateTowhook", nullptr, { "FortOctopusVehicle", "FortSpaghettiVehicle", nullptr }, { "ServerUpdateTowhook", nullptr }, false },

        // PlayerController Athena
        { "ServerAttemptAircraftJump", "ServerAttemptAircraftJumpVft", { "FortPlayerControllerAthena", "FortPlayerController", "FortControllerComponent_Aircraft", nullptr }, { "ServerAttemptAircraftJump", nullptr }, false },
        { "ServerAcknowledgePossession", "ServerAcknowledgePossessionVft", { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerAcknowledgePossession", nullptr }, false },
        { "ServerExecuteInventoryItem", "ServerExecuteInventoryItemVft", { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerExecuteInventoryItem", nullptr }, false },
        { "ServerExecuteInventoryWeapon", nullptr, { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerExecuteInventoryWeapon", nullptr }, false },
        { "ServerCreateBuildingActor", "ServerCreateBuildingActorVft", { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerCreateBuildingActor", nullptr }, false },
        { "ServerBeginEditingBuildingActor", "ServerBeginEditingBuildingActorVft", { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerBeginEditingBuildingActor", nullptr }, false },
        { "ServerEditBuildingActor", "ServerEditBuildingActorVft", { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerEditBuildingActor", nullptr }, false },
        { "ServerEndEditingBuildingActor", "ServerEndEditingBuildingActorVft", { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerEndEditingBuildingActor", nullptr }, false },
        { "ServerRepairBuildingActor", nullptr, { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerRepairBuildingActor", nullptr }, false },
        { "ServerAttemptInventoryDrop", "ServerAttemptInventoryDropVft", { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerAttemptInventoryDrop", "ServerSpawnInventoryDrop", nullptr }, false },
        { "ServerPlayEmoteItem", "ServerPlayEmoteItemVft", { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerPlayEmoteItem", nullptr }, false },
        { "ServerPlaySprayItem", nullptr, { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerPlaySprayItem", nullptr }, false },
        { "ServerClientIsReadyToRespawn", nullptr, { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerClientIsReadyToRespawn", nullptr }, false },
        { "ServerCheat", "ServerCheatVft", { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerCheat", nullptr }, false },
        { "ServerAttemptInteract", nullptr, { "FortPlayerControllerAthena", "FortPlayerController", "FortControllerComponent_Interaction", nullptr }, { "ServerAttemptInteract", nullptr }, false },
        { "ServerDropAllItems", nullptr, { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerDropAllItems", nullptr }, false },
        { "SpawnToyInstance", nullptr, { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "SpawnToyInstance", nullptr }, false },
        { "ServerTeleportToPlaygroundLobbyIsland", nullptr, { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerTeleportToPlaygroundLobbyIsland", nullptr }, false },
        { "ServerCraftSchematic", nullptr, { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerCraftSchematic", nullptr }, false },
        { "ServerGiveCreativeItem", nullptr, { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerGiveCreativeItem", nullptr }, false },
        { "ServerRequestSeatChange", nullptr, { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerRequestSeatChange", nullptr }, false },
        { "ServerLoadingScreenDropped", nullptr, { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerLoadingScreenDropped", nullptr }, false },
        { "ServerCreativeSetFlightSpeedIndex", nullptr, { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerCreativeSetFlightSpeedIndex", nullptr }, false },
        { "ServerCreativeSetFlightSprint", nullptr, { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerCreativeSetFlightSprint", nullptr }, false },
        { "ServerAwardVehicleTrickPoints", nullptr, { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerAwardVehicleTrickPoints", nullptr }, false },
        { "ServerOnMaterialSelection", "ServerOnMaterialSelectionVft", { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerOnMaterialSelection", nullptr }, false },
        { "ServerPlaySquadQuickChatMessage", nullptr, { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerPlaySquadQuickChatMessage", nullptr }, false },
        { nullptr, "ServerRestartPlayerVft", { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerRestartPlayer", nullptr }, false },
        { nullptr, "ServerSuicideVft", { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerSuicide", nullptr }, false },
        { nullptr, "ServerReturnToMainMenuVft", { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerReturnToMainMenu", nullptr }, false },
        { nullptr, "ServerSpectateActorVft", { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerSpectateActor", nullptr }, false },

        // Held object component
        { "PickupHeldObject", nullptr, { "FortHeldObjectComponent", nullptr }, { "PickupHeldObject", nullptr }, false },
        { "DropHeldObject", nullptr, { "FortHeldObjectComponent", nullptr }, { "DropHeldObject", nullptr }, false },
        { "PlaceHeldObject", nullptr, { "FortHeldObjectComponent", nullptr }, { "PlaceHeldObject", nullptr }, false },
        { "ThrowHeldObject", nullptr, { "FortHeldObjectComponent", nullptr }, { "ThrowHeldObject", nullptr }, false },

        // Indicated actors
        { "AddActorsToIndicatedList", nullptr, { "FortIndicatedActorManagementLibrary", "FortIndicatedActorLibrary", nullptr }, { "AddActorsToIndicatedList", nullptr }, false },

        // PlayerPawn Athena
        { "ServerHandlePickupInfo", "ServerHandlePickupInfoVft", { "FortPlayerPawnAthena", "FortPlayerPawn", nullptr }, { "ServerHandlePickupInfo", nullptr }, false },
        { "ServerHandlePickup", nullptr, { "FortPlayerPawnAthena", "FortPlayerPawn", nullptr }, { "ServerHandlePickup", nullptr }, false },
        { "ServerHandlePickupWithRequestedSwap", nullptr, { "FortPlayerPawnAthena", "FortPlayerPawn", nullptr }, { "ServerHandlePickupWithRequestedSwap", nullptr }, false },
        { "OnCapsuleBeginOverlap", nullptr, { "FortPlayerPawnAthena", "FortPlayerPawn", nullptr }, { "OnCapsuleBeginOverlap", nullptr }, false },
        { "ServerSendZiplineState", "ServerSendZiplineStateVft", { "FortPlayerPawnAthena", "FortPlayerPawn", nullptr }, { "ServerSendZiplineState", nullptr }, false },
        { "MovingEmoteStopped", nullptr, { "FortPlayerPawnAthena", "FortPlayerPawn", nullptr }, { "MovingEmoteStopped", nullptr }, false },
        { "ServerOnExitVehicle", nullptr, { "FortPlayerPawnAthena", "FortPlayerPawn", nullptr }, { "ServerOnExitVehicle", nullptr }, false },
        { "EmoteStopped", nullptr, { "FortPlayerPawnAthena", "FortPlayerPawn", nullptr }, { "EmoteStopped", nullptr }, false },
        { "EndSkydiving", "EndSkydivingVft", { "FortPlayerPawnAthena", "FortPlayerPawn", nullptr }, { "EndSkydiving", nullptr }, false },
        { "ServerReviveFromDBNO", nullptr, { "FortPlayerPawnAthena", "FortPlayerPawn", nullptr }, { "ServerReviveFromDBNO", nullptr }, false },
        { "ServerThrowCarriedPlayer", "ServerThrowCarriedPlayerVft", { "FortPlayerPawnAthena", "FortPlayerPawn", nullptr }, { "ServerThrowCarriedPlayer", nullptr }, false },
        { nullptr, "ServerHoistDBNOPlayerVft", { "FortPlayerPawnAthena", "FortPlayerPawn", nullptr }, { "ServerHoistDBNOPlayer", nullptr }, false },
        { nullptr, "ServerInterrogateDBNOPlayerVft", { "FortPlayerPawnAthena", "FortPlayerPawn", nullptr }, { "ServerInterrogateDBNOPlayer", nullptr }, false },

        // Abilities
        { "K2_ExecuteGameplayCue", nullptr, { "FortGameplayAbility", "GameplayAbility", nullptr }, { "K2_ExecuteGameplayCue", nullptr }, false },
        { "K2_ExecuteGameplayCueWithParams", nullptr, { "FortGameplayAbility", "GameplayAbility", nullptr }, { "K2_ExecuteGameplayCueWithParams", nullptr }, false },
        { "K2_AddGameplayCue", nullptr, { "FortGameplayAbility", "GameplayAbility", nullptr }, { "K2_AddGameplayCue", nullptr }, false },
        { "K2_AddGameplayCueWithParams", nullptr, { "FortGameplayAbility", "GameplayAbility", nullptr }, { "K2_AddGameplayCueWithParams", nullptr }, false },
        { nullptr, "InternalServerTryActivateAbilityVft", { "AbilitySystemComponent", "FortAbilitySystemComponent", nullptr }, { "ServerTryActivateAbilityWithEventData", "ServerTryActivateAbility", nullptr }, false },

        // Net dormancy 
        { "FlushNetDormancy", nullptr, { "Actor", nullptr }, { "FlushNetDormancy", nullptr }, true },
        { "SetNetDormancy", nullptr, { "Actor", nullptr }, { "SetNetDormancy", nullptr }, true },
        { "K2_GetActorLocation", nullptr, { "Actor", nullptr }, { "K2_GetActorLocation", nullptr }, false },

        // Quests / HUD
        { "SendComplexCustomStatEvent", nullptr, { "FortQuestManager", nullptr }, { "SendComplexCustomStatEvent", nullptr }, false },
        { "EnterCameraMode", nullptr, { "FortHUDContext", nullptr }, { "EnterCameraMode", nullptr }, false },

        // Misc VFTs using GetFunction
        { nullptr, "GivePickupToVft", { "FortPickup", "FortPickupAthena", nullptr }, { "GivePickupTo", nullptr }, false },
        { nullptr, "NeedsLoadForClientVft", { "Actor", nullptr }, { "NeedsLoadForClient", nullptr }, false },
        { nullptr, "DropItemsOnPawnDestructionVft", { "FortPlayerPawnAthena", "FortPlayerPawn", nullptr }, { "DropItemsOnPawnDestruction", nullptr }, false },
        { nullptr, "ServerSetMultiProductCosmeticLoadoutVft", { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerSetMultiProductCosmeticLoadout", nullptr }, false },
        { nullptr, "ForceEquipValidWeaponVft", { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ForceEquipValidWeapon", nullptr }, false },
        { nullptr, "SetLoadedAmmoVft", { "FortWorldItem", nullptr }, { "SetLoadedAmmo", nullptr }, false },
        { nullptr, "SetPhantomReserveAmmoVft", { "FortWorldItem", nullptr }, { "SetPhantomReserveAmmo", nullptr }, false },
    };

    for (auto& Target : UFuncTargets)
    {
        if (Target.ExecName)
        {
            uint64_t Addr = Target.UseImpl ? FindUFuncImpl(Target.Classes, Target.Functions) : FindUFuncExec(Target.Classes, Target.Functions);
            Entries.push_back({ Target.ExecName, Addr, false });
        }

        if (Target.VftName)
        {
            Entries.push_back({ Target.VftName, FindUFuncVft(Target.Classes, Target.Functions), true });
        }
    }

    printf("nulls / rettrues...\n");
    FindNullsAndRetTrues();

    const size_t TotalAttempted = Entries.size();
    std::vector<NamedAddr> FoundEntries;
    FoundEntries.reserve(Entries.size());

    for (auto& E : Entries)
    {
        if (E.Value)
        {
            FoundEntries.push_back(E);
            printf("  %-40s 0x%llX\n", E.Name, E.IsVft ? E.Value : Rel(E.Value));
        }
        else
        {
            printf("  %-40s miss\n", E.Name);
        }
    }

    Entries = std::move(FoundEntries);

    const std::string VersionStr = FormatVersion(FnVersion);

    std::ostringstream Out;
    Out << "// Generated by Helix's OffsetFinder (Gameserver / Erbium signatures), Fortnite version: " << VersionStr << "\n";
    Out << "// Engine: " << FormatVersion(EngineVersion) << " | Found " << Entries.size() << "/" << TotalAttempted << " named offsets\n";
    Out << "// Supported range: 1.7.2 - 30.00 may have partial support aobve (from https://github.com/plooshi/Erbium)\n";
    Out << "#pragma once\n";
    Out << "#include <stdint.h>\n";
    Out << "#include <vector>\n";
    Out << "#include <intrin.h>\n\n";
    Out << "class Helix\n";
    Out << "{\n";
    Out << "public:\n";
    Out << "\tclass Offsets\n";
    Out << "\t{\n";
    Out << "\tpublic:\n";
    Out << "\t\tstatic inline uint64_t ImageBase;\n";

    for (auto& E : Entries)
        EmitDecl(Out, E.Name, E.IsVft);

    Out << "\n";
    Out << "\t\tstatic inline std::vector<uint64_t> NullFuncs;\n";
    Out << "\t\tstatic inline std::vector<uint64_t> RetTrueFuncs;\n\n";
    Out << "\t\tstatic int Init()\n";
    Out << "\t\t{\n";
    Out << "\t\t\tImageBase = *(uint64_t*)(__readgsqword(0x60) + 0x10);\n\n";

    for (auto& E : Entries)
    {
        if (E.IsVft)
            EmitVft(Out, E.Name, (uint32_t)E.Value);
        else
            EmitRva(Out, E.Name, E.Value);
    }

    Out << "\n";
    Out << "\t\t\tNullFuncs.clear();\n";
    for (auto Addr : NullFuncs)
    {
        if (!Addr)
            continue;
        Out << "\t\t\tNullFuncs.push_back(ImageBase + 0x" << std::uppercase << std::hex << Rel(Addr) << std::dec << ");\n";
    }

    Out << "\n";
    Out << "\t\t\tRetTrueFuncs.clear();\n";
    for (auto Addr : RetTrueFuncs)
    {
        if (!Addr)
            continue;
        Out << "\t\t\tRetTrueFuncs.push_back(ImageBase + 0x" << std::uppercase << std::hex << Rel(Addr) << std::dec << ");\n";
    }

    Out << "\n";
    Out << "\t\t\treturn 0;\n";
    Out << "\t\t}\n";
    Out << "\t};\n";
    Out << "};\n";

    const std::string Result = Out.str();

    std::filesystem::path Path;
    if (!OutputPath.empty())
    {
        Path = OutputPath;
    }
    else
    {
        wchar_t ModulePath[MAX_PATH]{};
        GetModuleFileNameW(nullptr, ModulePath, MAX_PATH);
        Path = std::filesystem::path(ModulePath).parent_path() / ("GameserverOffsets-" + VersionStr + ".h");
    }

    {
        std::ofstream File(Path, std::ios::binary);
        File << Result;
    }

    CopyToClipboard(Result);

    printf("saved -> %s\n", Path.string().c_str());
    printf("(also on clipboard)\n");

    std::wstring Msg = L"dumped gameserver offsets to:\n" + Path.wstring() + L"\n\n(copied to clipboard too)";
    MessageBoxW(nullptr, Msg.c_str(), L"OffsetFinder", MB_OK | MB_ICONINFORMATION);

    return Result;
}

std::string OffsetFinder::GenerateRedirectOffsets(const std::wstring& OutputPath)
{
    printf("scanning redirect sigs...\n");

    // need version for the filename
    SDK::Init();
    const std::string VersionStr = FormatVersion(VersionInfo.FortniteVersion);

    uint64_t EOSBase = 0;
    auto Found = RedirectFinders::FindAll(EOSBase);

    for (auto& E : Found)
    {
        if (E.IsVft || E.IsMemberOffset)
            printf("  %-40s 0x%llX\n", E.Name, E.Absolute);
        else if (E.RelativeToEOS)
            printf("  %-40s EOS+0x%llX\n", E.Name, E.Absolute - EOSBase);
        else
            printf("  %-40s 0x%llX\n", E.Name, Rel(E.Absolute));
    }

    std::ostringstream Out;
    Out << "// Generated by Helix's OffsetFinder (Redirect / Tellurium + Starfall), Fortnite version: " << VersionStr << "\n";
    Out << "// Patterns from https://github.com/plooshi/Tellurium and https://github.com/plooshi/Starfall\n";
    Out << "// Found " << Found.size() << " offsets\n";
    Out << "#pragma once\n";
    Out << "#include <stdint.h>\n";
    Out << "#include <intrin.h>\n";
    Out << "#include <Windows.h>\n\n";
    Out << "class Helix\n";
    Out << "{\n";
    Out << "public:\n";
    Out << "\tclass Offsets\n";
    Out << "\t{\n";
    Out << "\tpublic:\n";
    Out << "\t\tstatic inline uint64_t ImageBase;\n";
    if (EOSBase)
        Out << "\t\tstatic inline uint64_t EOSImageBase;\n";

    for (auto& E : Found)
    {
        if (E.IsVft)
            Out << "\t\tstatic inline uint32_t " << E.Name << ";\n";
        else
            Out << "\t\tstatic inline uint64_t " << E.Name << ";\n";
    }

    Out << "\n";
    Out << "\t\tstatic int Init()\n";
    Out << "\t\t{\n";
    Out << "\t\t\tImageBase = *(uint64_t*)(__readgsqword(0x60) + 0x10);\n";
    if (EOSBase)
        Out << "\t\t\tEOSImageBase = (uint64_t)GetModuleHandleA(\"EOSSDK-Win64-Shipping.dll\");\n";
    Out << "\n";

    for (auto& E : Found)
    {
        if (E.IsVft || E.IsMemberOffset)
        {
            Out << "\t\t\t" << E.Name << " = 0x" << std::uppercase << std::hex << E.Absolute << std::dec << ";\n";
        }
        else if (E.RelativeToEOS)
        {
            Out << "\t\t\t" << E.Name << " = EOSImageBase + 0x" << std::uppercase << std::hex << (E.Absolute - EOSBase) << std::dec << ";\n";
        }
        else
        {
            Out << "\t\t\t" << E.Name << " = ImageBase + 0x" << std::uppercase << std::hex << Rel(E.Absolute) << std::dec << ";\n";
        }
    }

    Out << "\n";
    Out << "\t\t\treturn 0;\n";
    Out << "\t\t}\n";
    Out << "\t};\n";
    Out << "};\n";

    const std::string Result = Out.str();

    std::filesystem::path Path;
    if (!OutputPath.empty())
    {
        Path = OutputPath;
    }
    else
    {
        wchar_t ModulePath[MAX_PATH]{};
        GetModuleFileNameW(nullptr, ModulePath, MAX_PATH);
        Path = std::filesystem::path(ModulePath).parent_path() / ("RedirectOffsets-" + VersionStr + ".h");
    }

    {
        std::ofstream File(Path, std::ios::binary);
        File << Result;
    }

    CopyToClipboard(Result);

    printf("saved -> %s\n", Path.string().c_str());
    printf("(also on clipboard)\n");

    std::wstring Msg = L"dumped redirect offsets to:\n" + Path.wstring() + L"\n\n(copied to clipboard too)";
    MessageBoxW(nullptr, Msg.c_str(), L"OffsetFinder", MB_OK | MB_ICONINFORMATION);

    return Result;
}
