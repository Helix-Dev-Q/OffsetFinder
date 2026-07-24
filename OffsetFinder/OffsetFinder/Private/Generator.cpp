#include "pch.h"

#include "../Public/Generator.h"
#include "../Public/Finder.h"
#include "../Public/RedirectFinder.h"
#include "../Public/Precision.h"

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

    uint64_t SafeU64(uint64_t (*Fn)())
    {
        __try
        {
            return Fn();
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }
    }

    uint32_t SafeU32(uint32_t (*Fn)())
    {
        __try
        {
            return Fn();
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }
    }

    void SafeVoid(void (*Fn)())
    {
        __try
        {
            Fn();
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    uint64_t SafeFindUFunc(const char* const* Classes, const char* const* Functions, bool UseImpl)
    {
        __try
        {
            return UseImpl ? FindUFuncImpl(Classes, Functions) : FindUFuncExec(Classes, Functions);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }
    }

    uint32_t SafeFindUFuncVft(const char* const* Classes, const char* const* Functions)
    {
        __try
        {
            return FindUFuncVft(Classes, Functions);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }
    }

    uint64_t FindGWorld()
    {
        auto SRef = Precision::FindStringRefSmart(L"UWorld::CleanupWorld");

        if (SRef)
        {
            for (int i = 0; i < 0x400; i++)
            {
                if (!Precision::InTextRange(SRef - i, 3))
                    break;
                auto Ptr = (uint8_t*)(SRef - i);
                if (*Ptr == 0x48 && *(Ptr + 1) == 0x8B && (*(Ptr + 2) == 0x05 || *(Ptr + 2) == 0x0D || *(Ptr + 2) == 0x1D))
                {
                    auto Addr = Memcury::Scanner(Ptr).RelativeOffset(3).Get();
                    if (Precision::IsReadableDataPtr(Addr))
                        return Addr;
                }
                if (*Ptr == 0x48 && *(Ptr + 1) == 0x89 && (*(Ptr + 2) == 0x05 || *(Ptr + 2) == 0x0D || *(Ptr + 2) == 0x1D))
                {
                    auto Addr = Memcury::Scanner(Ptr).RelativeOffset(3).Get();
                    if (Precision::IsReadableDataPtr(Addr))
                        return Addr;
                }
            }
        }

        const double FN = VersionInfo.FortniteVersion;
        const double UE = VersionInfo.EngineVersion;
        std::vector<const char*> Patterns;
        if (UE >= 5.0 || FN >= 20.00)
        {
            Patterns = {
                "48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ? 48 85 C9 74 ? 48 8B 49",
                "48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ? 48 85 C9 74 ? E8",
                "48 8B 1D ? ? ? ? 48 85 DB 74 3B 41 B0 01",
                "48 89 05 ? ? ? ? 48 8B 4B ? E8",
            };
        }
        else
        {
            Patterns = {
                "48 8B 1D ? ? ? ? 48 85 DB 74 3B 41 B0 01",
                "48 89 05 ? ? ? ? 48 8B 4B ? E8",
                "48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ? 48 85 C9 74 06 48 8B 49 70",
            };
        }

        for (auto Pattern : Patterns)
        {
            for (auto Hit : Precision::FindAllPatterns(Pattern))
            {
                auto Addr = Memcury::Scanner(Hit).RelativeOffset(3).Get();
                if (Precision::IsReadableDataPtr(Addr))
                    return Addr;
            }
        }

        return 0;
    }

    uint64_t FindGEngine()
    {
        const double UE = VersionInfo.EngineVersion;
        std::vector<const char*> Patterns;
        if (UE >= 5.0)
        {
            Patterns = {
                "48 8B 0D ? ? ? ? 48 85 C9 74 ? E8 ? ? ? ? 48 8B 0D",
                "48 8B 0D ? ? ? ? 48 8B D8 48 85 C9 0F 84",
                "48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ? 48 85 C9 74 ? 48 8B 49 70",
            };
        }
        else
        {
            Patterns = {
                "48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ? 48 85 C9 74 ? 48 8B 49 70",
                "48 8B 0D ? ? ? ? 48 85 C9 74 ? E8 ? ? ? ? 48 8B 0D",
                "48 8B 0D ? ? ? ? 48 8B D8 48 85 C9 0F 84",
            };
        }

        for (auto Pattern : Patterns)
        {
            for (auto Hit : Precision::FindAllPatterns(Pattern))
            {
                auto Addr = Memcury::Scanner(Hit).RelativeOffset(3).Get();
                if (Precision::IsReadableDataPtr(Addr))
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

    printf("\n--- gameserver offsets ---\n");

    struct NamedAddr
    {
        const char* Name;
        uint64_t Value;
        bool IsVft;
    };

    std::vector<NamedAddr> Entries;
    Entries.reserve(256);

    auto HasEntry = [&](const char* Name) -> bool
    {
        for (auto& E : Entries)
        {
            if (E.Name && Name && strcmp(E.Name, Name) == 0)
                return true;
        }
        return false;
    };

    auto Push = [&](const char* Name, uint64_t Value, bool IsVft = false)
    {
        if (!Name || HasEntry(Name))
            return;
        Entries.push_back({ Name, Value, IsVft });
        if (Value)
            printf("  %-40s 0x%llX\n", Name, IsVft ? Value : Rel(Value));
        else
            printf("  %-40s NOT FOUND\n", Name);
        fflush(stdout);
    };

    auto PushAlias = [&](const char* Name, uint64_t Value, bool IsVft = false)
    {
        if (!Value || !Name || HasEntry(Name))
            return;
        Entries.push_back({ Name, Value, IsVft });
    };

    printf("\n--- globals / sdk ---\n");
    const uint64_t GWorld = FindGWorld();
    const uint64_t GEngine = FindGEngine();
    const uint64_t GUObjectArray = Offsets::GObjectsChunked ? Offsets::GObjectsChunked : Offsets::GObjectsUnchunked;
    const uint64_t GIsClient = FindGIsClient();
    const uint64_t GIsServer = FindGIsServer();

    Push("GWorld", GWorld);
    Push("GEngine", GEngine);
    Push("GUObjectArray", GUObjectArray);
    PushAlias("GObjects", GUObjectArray);
    PushAlias("GObjectsChunked", Offsets::GObjectsChunked);
    PushAlias("GObjectsUnchunked", Offsets::GObjectsUnchunked);
    Push("GIsClient", GIsClient);
    Push("GIsServer", GIsServer);
    Push("Realloc", Offsets::Realloc);
    PushAlias("FMemoryRealloc", Offsets::Realloc);
    Push("AppendString", Offsets::AppendString);
    PushAlias("FName_AppendString", Offsets::AppendString);
    Push("ToString", Offsets::ToString);
    PushAlias("FName_ToString", Offsets::ToString);
    Push("Step", Offsets::Step);
    Push("StepExplicitProperty", Offsets::StepExplicitProperty);
    Push("GetInterfaceAddress", Offsets::GetInterfaceAddress);
    Push("StaticFindObject", Offsets::StaticFindObject);
    Push("StaticLoadObject", Offsets::StaticLoadObject);
    Push("FNameCtor", Offsets::FNameConstructor);
    PushAlias("FName_Constructor", Offsets::FNameConstructor);
    Push("SpawnActorTransform", Offsets::SpawnActor);
    PushAlias("SpawnActor", Offsets::SpawnActor);
    Push("ProcessEventVft", Offsets::ProcessEventVft, true);

    printf("\n--- net / listen ---\n");
    const uint64_t AttemptDerive = FindAttemptDeriveFromURL();
    const uint64_t WorldNetMode = FindGetNetMode();
    const uint64_t DispatchRequest = FindSendRequestNow();

    if (NeedsAttemptDeriveFromURL())
    {
        Push("AttemptDeriveFromURL", AttemptDerive);
        Push("WorldNetMode", AttemptDerive ? AttemptDerive : WorldNetMode);
        if (NeedsGetNetModeAlongsideAttemptDerive())
            PushAlias("GetNetMode", WorldNetMode);
        else if (WorldNetMode && WorldNetMode != AttemptDerive)
            PushAlias("GetNetMode", WorldNetMode);
    }
    else
    {
        Push("WorldNetMode", WorldNetMode);
        PushAlias("GetNetMode", WorldNetMode);
        if (AttemptDerive)
            Push("AttemptDeriveFromURL", AttemptDerive);
    }

    Push("GetWorldContext", FindGetWorldContext());
    Push("CreateNetDriver", FindCreateNetDriver());
    Push("CreateNetDriverWorldContext", FindCreateNetDriverWorldContext());
    Push("InitListen", FindInitListen());
    Push("SetWorld", FindSetWorld());
    Push("TickFlush", FindTickFlush());
    Push("ServerReplicateActors", FindServerReplicateActors());
    Push("DispatchRequest", DispatchRequest);
    PushAlias("SendRequestNow", DispatchRequest);
    Push("GetMaxTickRate", FindGetMaxTickRate());
    Push("Listen", FindListenCall());
    Push("IsNetReady", FindIsNetReady());
    Push("CallPreReplication", FindCallPreReplication());
    Push("SendClientAdjustment", FindSendClientAdjustment());
    Push("SetChannelActor", FindSetChannelActor());
    Push("SetChannelActorForDestroy", FindSetChannelActorForDestroy());
    Push("CreateChannel", FindCreateChannel());
    Push("ReplicateActor", FindReplicateActor());
    Push("CloseActorChannel", FindCloseActorChannel());
    Push("ClientHasInitializedLevelFor", FindClientHasInitializedLevelFor());
    Push("StartBecomingDormant", FindStartBecomingDormant());
    Push("FlushDormancy", FindFlushDormancy());
    Push("SendDestructionInfo", FindSendDestructionInfo());
    Push("UpdateIrisReplicationViews", FindUpdateIrisReplicationViews());
    Push("PreSendUpdate", FindPreSendUpdate());
    Push("IsNetRelevantForVft", (uint64_t)FindIsNetRelevantForVft(), true);

    printf("\n--- abilities / inventory / build ---\n");
    const uint64_t ConstructAbilitySpec = FindConstructAbilitySpec();
    Push("GiveAbility", FindGiveAbility());
    Push("ConstructAbilitySpec", ConstructAbilitySpec);
    PushAlias("AbilitySpecDefaultConstructor", ConstructAbilitySpec);
    Push("InternalTryActivateAbility", FindInternalTryActivateAbility());
    Push("GiveAbilityAndActivateOnce", FindGiveAbilityAndActivateOnce());
    Push("ClearAbility", FindClearAbility());
    Push("ApplyCharacterCustomization", FindApplyCharacterCustomization());
    Push("RemoveInventoryItem", FindRemoveInventoryItem());
    Push("RemoveInventoryStateValue", FindRemoveInventoryStateValue());
    Push("SetInventoryStateValue", FindSetInventoryStateValue());
    Push("SetPickupItems", FindSetPickupItems());
    Push("SetPickupTarget", FindSetPickupTarget());
    Push("OnItemInstanceAddedVft", FindOnItemInstanceAddedVft(), true);
    Push("CantBuild", FindCantBuild());
    Push("ReplaceBuildingActor", FindReplaceBuildingActor());
    Push("InitializeBuildingActor", FindInitializeBuildingActor());
    Push("PostInitializeSpawnedBuildingActor", FindPostInitializeSpawnedBuildingActor());
    Push("PayBuildableClassPlacementCost", FindPayBuildableClassPlacementCost());
    Push("CanAffordToPlaceBuildableClass", FindCanAffordToPlaceBuildableClass());
    Push("CanPlaceBuildableClassInStructuralGrid", FindCanPlaceBuildableClassInStructuralGrid());
    Push("SpawnDecoVft", FindSpawnDecoVft(), true);
    Push("ShouldAllowServerSpawnDecoVft", FindShouldAllowServerSpawnDecoVft(), true);
    Push("SetIsDoorOpen", FindSetIsDoorOpen());
    Push("SelectAndSetupMyBuildingLevel", FindSelectAndSetupMyBuildingLevel());
    Push("StreamInMyBuilding", FindStreamInMyBuilding());

    printf("\n--- misc hooks ---\n");
    Push("CheckCheckpointHeartBeat", FindCheckCheckpointHeartBeat());
    Push("ApplyHomebaseEffectsOnPlayerSetup", FindApplyHomebaseEffectsOnPlayerSetup());
    Push("RetFalse", FindRetFalse());
    Push("NetModePatch", FindNetModePatch());
    Push("CrashSomething", FindCrashSomething());
    Push("OverrideCosmeticLoadout", FindOverrideCosmeticLoadout());
    Push("PedestalBeginPlay", FindPedestalBeginPlay());

    printf("\n--- gamemode / zone / aircraft ---\n");
    const uint64_t SetupSafeZonePhase = FindHandlePostSafeZonePhaseChanged();
    const uint64_t GameSessionPatch = FindGameSessionPatch();
    const uint64_t HandleZipline = FindOnRep_ZiplineState();
    const uint64_t ControllerReset = FindReset();
    Push("SetupSafeZonePhase", SetupSafeZonePhase);
    PushAlias("HandlePostSafeZonePhaseChanged", SetupSafeZonePhase);
    Push("SpawnLoot", FindSpawnLoot());
    Push("FinishedTargetSpline", FindFinishedTargetSpline());
    Push("PickTeam", FindPickTeam());
    Push("KickPlayer", FindKickPlayer());
    Push("EncryptionPatch", FindEncryptionPatch());
    Push("GameSessionPatch", GameSessionPatch);
    PushAlias("ChangeGameSessionId", GameSessionPatch);
    Push("RemoveFromAlivePlayers", FindRemoveFromAlivePlayers());
    Push("StartAircraftPhase", FindStartAircraftPhase());
    Push("EnterAircraft", FindEnterAircraft());
    Push("HandleZiplineStateChanged", HandleZipline);
    PushAlias("OnRep_ZiplineState", HandleZipline);
    Push("GetPlayerViewPoint", FindGetPlayerViewPoint());
    Push("GetNamePool", FindGetNamePool());
    Push("SpawnInitialSafeZone", FindSpawnInitialSafeZone());
    Push("UpdateSafeZonesPhase", FindUpdateSafeZonesPhase());
    Push("HandleMatchHasStarted", FindHandleMatchHasStarted());
    Push("InitializeFlightPath", FindInitializeFlightPath());
    Push("ControllerReset", ControllerReset);
    PushAlias("Reset", ControllerReset);
    Push("NotifyGameMemberAdded", FindNotifyGameMemberAdded());
    Push("SetGamePhase", FindSetGamePhase());
    Push("LoadPlayset", FindLoadPlayset());
    Push("SetState", FindSetState());
    Push("MinigameSettingsBuildingBeginPlay", SafeU64(FindMinigameSettingsBuilding__BeginPlay));
    Push("PickSupplyDropLocation", SafeU64(FindPickSupplyDropLocation));
    Push("InitializePlayerGameplayAbilities", SafeU64(FindInitializePlayerGameplayAbilities));
    Push("QueueStatEvent", SafeU64(FindQueueStatEvent));
    Push("FinishWorldInitialization", SafeU64(FindFinishWorldInitialization));
    Push("ActivatePhase", SafeU64(FindActivatePhase));

    printf("\n--- ufunctions / exec hooks ---\n");
    fflush(stdout);

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

        // Extra common GS hooks
        { "ServerReadyToStartMatch", nullptr, { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerReadyToStartMatch", nullptr }, false },
        { "ServerSetClientHasFinishedLoading", nullptr, { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ServerSetClientHasFinishedLoading", nullptr }, false },
        { "ClientReportDamagedResourceBuilding", nullptr, { "FortPlayerControllerAthena", "FortPlayerController", nullptr }, { "ClientReportDamagedResourceBuilding", nullptr }, false },
        { "NetMulticast_Athena_BatchedDamageCues", nullptr, { "FortPawn", "FortPlayerPawn", nullptr }, { "NetMulticast_Athena_BatchedDamageCues", nullptr }, false },
        { "ClientOnPawnDied", nullptr, { "FortPlayerControllerZone", "FortPlayerControllerAthena", nullptr }, { "ClientOnPawnDied", nullptr }, false },
        { "OnRep_CurrentHealth", nullptr, { "FortPawn", "FortPlayerPawn", nullptr }, { "OnRep_CurrentHealth", nullptr }, false },
        { "OnRep_bIsDBNO", nullptr, { "FortPawn", "FortPlayerPawn", nullptr }, { "OnRep_bIsDBNO", nullptr }, false },
        { "ServerChangeName", nullptr, { "PlayerController", nullptr }, { "ServerChangeName", nullptr }, false },
        { "ServerNotifyLoadedWorld", nullptr, { "PlayerController", nullptr }, { "ServerNotifyLoadedWorld", nullptr }, false },
        { "ServerUpdateLevelVisibility", nullptr, { "PlayerController", nullptr }, { "ServerUpdateLevelVisibility", nullptr }, false },
        { "ServerUpdateMultipleLevelsVisibility", nullptr, { "PlayerController", nullptr }, { "ServerUpdateMultipleLevelsVisibility", nullptr }, false },
        { "ReceiveBeginPlay", nullptr, { "Actor", nullptr }, { "ReceiveBeginPlay", nullptr }, false },
        { "ReceiveEndPlay", nullptr, { "Actor", nullptr }, { "ReceiveEndPlay", nullptr }, false },
        { "K2_OnBecomeViewTarget", nullptr, { "Actor", nullptr }, { "K2_OnBecomeViewTarget", nullptr }, false },
        { "GetLifetime", nullptr, { "Actor", nullptr }, { "GetLifetime", nullptr }, false },
    };

    for (auto& Target : UFuncTargets)
    {
        if (Target.ExecName)
            Push(Target.ExecName, SafeFindUFunc(Target.Classes, Target.Functions, Target.UseImpl), false);

        if (Target.VftName)
            Push(Target.VftName, SafeFindUFuncVft(Target.Classes, Target.Functions), true);
    }

    printf("\n--- nulls / rettrues ---\n");
    fflush(stdout);
    SafeVoid(FindNullsAndRetTrues);

    size_t NullCount = 0;
    for (auto Addr : NullFuncs)
    {
        if (!Addr)
            continue;
        NullCount++;
        printf("  NullFuncs[%zu]                            0x%llX\n", NullCount - 1, Rel(Addr));
    }
    if (!NullCount)
        printf("  NullFuncs                                 NONE\n");

    size_t RetTrueCount = 0;
    for (auto Addr : RetTrueFuncs)
    {
        if (!Addr)
            continue;
        RetTrueCount++;
        printf("  RetTrueFuncs[%zu]                         0x%llX\n", RetTrueCount - 1, Rel(Addr));
    }
    if (!RetTrueCount)
        printf("  RetTrueFuncs                              NONE\n");

    const size_t TotalAttempted = Entries.size();
    std::vector<NamedAddr> FoundEntries;
    FoundEntries.reserve(Entries.size());
    for (auto& E : Entries)
    {
        if (E.Value)
            FoundEntries.push_back(E);
    }
    Entries = std::move(FoundEntries);

    printf("--- found %zu/%zu gameserver offsets (+ %zu nulls, %zu rettrues) ---\n\n",
        Entries.size(), TotalAttempted, NullCount, RetTrueCount);

    const std::string VersionStr = FormatVersion(FnVersion);

    std::ostringstream Out;
    Out << "// Generated by Helix's OffsetFinder, Fortnite version: " << VersionStr << "\n";
    Out << "// UE " << FormatVersion(EngineVersion) << "\n";
    Out << "#pragma once\n";
    Out << "#include <stdint.h>\n";
    Out << "#include <vector>\n";
    Out << "#include <intrin.h>\n\n";
    Out << "class Offset\n";
    Out << "{\n";
    Out << "public:\n";
    Out << "\tclass Finder\n";
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
    fflush(stdout);

    std::wstring Msg = L"dumped gameserver offsets to:\n" + Path.wstring() + L"\n\n(copied to clipboard too)";
    MessageBoxW(nullptr, Msg.c_str(), L"OffsetFinder", MB_OK | MB_ICONINFORMATION);

    return Result;
}

std::string OffsetFinder::GenerateRedirectOffsets(const std::wstring& OutputPath)
{
    printf("scanning redirect sigs...\n");
    SDK::Init();
    const std::string VersionStr = FormatVersion(VersionInfo.FortniteVersion);

    uint64_t EOSBase = 0;
    auto Found = RedirectFinders::FindAll(EOSBase);

    std::ostringstream Out;
    Out << "// Generated by Helix's OffsetFinder, Fortnite version: " << VersionStr << "\n";
    Out << "// UE " << FormatVersion(VersionInfo.EngineVersion) << "\n";
    Out << "#pragma once\n";
    Out << "#include <stdint.h>\n";
    Out << "#include <intrin.h>\n";
    Out << "#include <Windows.h>\n\n";
    Out << "class Offset\n";
    Out << "{\n";
    Out << "public:\n";
    Out << "\tclass Finder\n";
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
    fflush(stdout);

    std::wstring Msg = L"dumped redirect offsets to:\n" + Path.wstring() + L"\n\n(copied to clipboard too)";
    MessageBoxW(nullptr, Msg.c_str(), L"OffsetFinder", MB_OK | MB_ICONINFORMATION);

    return Result;
}
