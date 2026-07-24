#include "pch.h"

#include "../Public/Finder.h"
#include "../Public/Precision.h"

uint64_t FindGIsClient()
{
    static uintptr_t GIsClient = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        std::vector<std::vector<uint8_t>> GIsClientLoads = {
            { 0x88, 0x05 },
            { 0xC6, 0x05 },
            { 0x88, 0x1D },
            { 0x44, 0x88 },
            { 0x40, 0x88 }
        };

        auto sRef = Precision::FindStringRefSmart(L"AllowCommandletRendering");
        if (!sRef)
            sRef = Precision::FindStringRefSmart(L"llowCommandletRendering"); // bro why

        int Skip = 2;
        uint8_t correctByte = 0;
        for (int i = 0; i < 0x100; i++)
        {
            auto Ptr = (uint8_t*)(sRef - i);

            for (auto& Load : GIsClientLoads)
            {
                bool bMatches = true;
                for (int x = 0; x < Load.size(); x++)
                {
                    if (Load[x] != *(Ptr + x))
                    {
                        bMatches = false;
                        break;
                    }
                }
                if (!bMatches)
                    continue;
                if ((Load[0] == 0x44 || Load[0] == 0x40) && (*(Ptr + 2) == 0x74 || *(Ptr + 2) == 0x30))
                    continue;
                if (!correctByte)
                    correctByte = Load[0];
                else if (Load[0] != correctByte)
                    continue;
                if (Skip > 0)
                {
                    Skip--;
                    continue;
                }

                return GIsClient = Memcury::Scanner(Ptr).RelativeOffset((Load[0] == 0x44 || Load[0] == 0x40) ? 3 : 2, Load[0] == 0xc6).Get();
            }
        }
    }

    return GIsClient;
}

uint64_t FindGIsServer()
{
    static uintptr_t GIsServer = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        std::vector<std::vector<uint8_t>> GIsServerLoads = {
            { 0x88, 0x05 },
            { 0xC6, 0x05 },
            { 0x88, 0x1D },
            { 0x44, 0x88 },
            { 0x40, 0x88 }
        };

        auto sRef = Precision::FindStringRefSmart(L"AllowCommandletRendering");
        if (!sRef)
            sRef = Precision::FindStringRefSmart(L"llowCommandletRendering"); // bro why

        int Skip = 1;
        uint8_t correctByte = 0;
        for (int i = 0; i < 0x100; i++)
        {
            auto Ptr = (uint8_t*)(sRef - i);

            for (auto& Load : GIsServerLoads)
            {
                bool bMatches = true;
                for (int x = 0; x < Load.size(); x++)
                {
                    if (Load[x] != *(Ptr + x))
                    {
                        bMatches = false;
                        break;
                    }
                }
                if (!bMatches)
                    continue;
                if ((Load[0] == 0x44 || Load[0] == 0x40) && (*(Ptr + 2) == 0x74 || *(Ptr + 2) == 0x30))
                    continue;
                if (!correctByte)
                    correctByte = Load[0];
                else if (Load[0] != correctByte)
                    continue;
                if (Skip > 0)
                {
                    Skip--;
                    continue;
                }

                return GIsServer = Memcury::Scanner(Ptr).RelativeOffset((Load[0] == 0x44 || Load[0] == 0x40) ? 3 : 2, Load[0] == 0xc6).Get();
            }
        }
    }

    return GIsServer;
}

uint64_t FindGetNetMode()
{
    static uint64_t GetNetMode = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        if (floor(VersionInfo.FortniteVersion) == 18)
        {
            GetNetMode = Precision::Pattern("48 83 EC 28 48 83 79 ? ? 75 20 48 8B 91 ? ? ? ? 48 85 D2 74 1E 48 8B 02 48 8B CA FF 90");
            return GetNetMode;
        }

        auto sRef = Precision::FindStringRefSmart(L"PREPHYSBONES");
        if (!sRef)
            return GetNetMode;

        const uint64_t Container = Precision::WalkBackToPrologueFromString(sRef);
        if (!Container)
            return GetNetMode;

        uint64_t Best = 0;
        int BestScore = -1;
        for (int i = 0; i < 0x200; i++)
        {
            if (!Precision::InTextRange(Container + i, 5))
                break;
            auto Ptr = (uint8_t*)(Container + i);
            if (*Ptr != 0xE8)
                continue;
            if (i > 0 && (*(Ptr - 1) == 0x8b || *(Ptr - 1) == 0xe7 || *(Ptr - 1) == 0x24))
                continue;

            const uint64_t Target = Memcury::Scanner(Ptr).RelativeOffset(1).Get();
            if (!Precision::InText(Target))
                continue;

            int Score = 1;
            auto T = (uint8_t*)Target;
            if (!Precision::InTextRange(Target, 4))
                continue;
            if (T[0] == 0x48 && T[1] == 0x83 && T[2] == 0xEC)
                Score += 8;
            if (T[0] == 0x40 && T[1] == 0x53)
                Score += 4;
            if (Precision::InText(Target - 1) && Precision::LooksLikeFuncBoundaryByte(T[-1]))
                Score += 3;

            if (Score > BestScore)
            {
                BestScore = Score;
                Best = Target;
            }
        }

        GetNetMode = Best ? Best : Memcury::Scanner(Container).ScanFor({ 0xE8 }).RelativeOffset(1).Get();
        if (GetNetMode && !Precision::InText(GetNetMode))
            GetNetMode = 0;
    }

    return GetNetMode;
}

uint64_t FindAttemptDeriveFromURL()
{
    static uint64_t AttemptDerive = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        if (!NeedsAttemptDeriveFromURL())
            return AttemptDerive;

        std::vector<const char*> Sigs = {
            "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? 4C 8B C1",
            "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? 48 8B D1",
            "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? 4C 8B D1",
        };
        if (!NeedsGetNetModeAlongsideAttemptDerive())
            Sigs.push_back("48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? 4C 8B D1");

        std::vector<uint64_t> Hits;
        for (auto Sig : Sigs)
        {
            auto Found = Precision::FindAllPatterns(Sig);
            Hits.insert(Hits.end(), Found.begin(), Found.end());
        }

        AttemptDerive = Precision::PickBest(Hits, [](uint64_t Func, uint64_t) {
            int Score = 0;
            if (Precision::FuncContainsPattern(Func, "48 81 EC", 0x20))
                Score += 8;
            auto P = (uint8_t*)Func;
            if (Precision::InTextRange(Func, 4) && P[0] == 0x48 && P[1] == 0x89 && P[2] == 0x5C)
                Score += 4;
            return Score;
        });

        if (!AttemptDerive)
            AttemptDerive = Precision::PickBest(Hits);
    }

    return AttemptDerive;
}

uint64_t FindGetWorldContext()
{
    static uint64_t GetWorldContext = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        GetWorldContext = Precision::Patterns({
            "48 8B 81 ? ? ? ? 48 63 89 ? ? ? ? 4C 8D 04 C8 49 3B C0 74 ? 48 8B 08 48 39 91 80 02 00 00 75 ? 48 8B C1 C3",
            "48 8B 81 ? ? ? ? 48 63 89 ? ? ? ? 4C 8D 04 C8 49 3B C0 74 ? 48 8B 08 48 39 91 B8 02 00 00 75 ? 48 8B C1 C3",
            "48 8B 81 ? ? ? ? 48 63 89 ? ? ? ? 4C 8D 04 C8 49 3B C0 74 ? 48 8B 08 48 39 91 70 02 00 00 75 ? 48 8B C1 C3",
            "48 8B 81 ? ? ? ? 48 63 89 ? ? ? ? 4C 8D 04 C8 49 3B C0 74 ? 48 8B 08 48 39 91 ? ? ? ? 75 ? 48 8B C1 C3",
            "48 8B 81 ? ? ? ? 48 63 89 ? ? ? ? 4C 8D 04 C8 49 3B C0 74 ? 48 8B 08 48 39 91 B8 02 00 00 74 ? 48 83 C0 08 EB ??",
            "48 8B 81 ? ? ? ? 48 63 89 ? ? ? ? 4C 8D 04 C8 49 3B C0 74 ? 48 8B 08 48 39 91 ? ? ? ? 74 ? 48 83 C0 08 EB ??",
            "40 53 48 83 EC ?? F6 41 08 10 48 8B D9 75 ?? 48 8B 41 20",
        });
    }
    return GetWorldContext;
}

uint64_t FindCreateNetDriver()
{
    static uint64_t CreateNetDriver = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        CreateNetDriver = Precision::Patterns({
            "49 8B D8 48 8B F9 E8 ?? ?? ?? ?? 48 8B D0 4C 8B C3 48 8B CF 48 8B 5C 24 ?? 48 83 C4 ?? 5F E9 ?? ?? ?? ??",
            "E8 ?? ?? ?? ?? 4C 8B 44 24 ?? 48 8B D0 48 8B CB E8 ?? ?? ?? ?? 48 83 C4 ?? 5B C3",
            "33 D2 E8 ?? ?? ?? ?? 48 8B D0 4C 8B C3 48 8B CF E8 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 83 C4 ?? 5F C3",
        });
    }

    return CreateNetDriver;
}

uint64_t FindCreateNetDriverWorldContext()
{
    static uint64_t CreateNetDriver = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        if (std::floor(VersionInfo.FortniteVersion) == 19)
        {
            CreateNetDriver = Precision::Pattern("41 56 48 83 EC ? 48 63 81 ? ? ? ? 48 8D ? ? ? ? ? 48 8B B9 ? ? ? ? 4C 8B F2");
            return CreateNetDriver;
        }

        if (VersionInfo.FortniteVersion >= 20)
        {
            CreateNetDriver = Precision::Patterns({
                "41 56 41 57 48 83 EC ? 48 63 81 ? ? ? ? 48 8D ? ? ? ? ? 48 8B B9",
                "41 56 41 57 48 8B EC 48 83 EC ? 48 63 81 ? ? ? ? 48 8D ? ? ? ? ? 48 8B B1",
                "41 56 41 57 48 8B EC 48 83 EC ? 48 63 81 ? ? ? ? 48 8D ? ? ? ? ? 4C 8B B1",
                "41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 48 63 81 ? ? ? ? 4C 8D 3D",
                "41 56 41 57 48 83 EC ? 4C 8B EA 4C 8B E1 48 81 C1",
                "41 56 41 57 48 83 EC ? 48 63 81 ? ? ? ? 4C 8D 35",
            });
            return CreateNetDriver;
        }

        auto Hits = Precision::FindAllPatterns("C7 44 24 ? 00 20 00 00 33 D2 48 8B C8 E8 ? ? ? ? 48 ?? 4C");
        if (Hits.empty())
            Hits = Precision::FindAllPatterns("C7 44 24 ? 00 20 00 00 48 8B C8 E8 ? ? ? ? 48 ?? 4C");
        CreateNetDriver = Precision::PickBest(Hits);
    }

    return CreateNetDriver;
}

uint64_t FindInitListen()
{
    static uint64_t InitListen = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        auto sRef = Precision::FindStringRefSmart(L"%s IpNetDriver listening on port %i");

        if (sRef)
        {
            int Skip = VersionInfo.EngineVersion >= 5.0 ? 0 : 1;
            for (int i = 0; i < 2000; i++)
            {
                auto Ptr = (uint8_t*)(sRef - i);
                if (!Precision::IsPrologue(Ptr))
                    continue;
                if (!(Ptr[0] == 0x48 && Ptr[1] == 0x89 && Ptr[2] == 0x5C) && !(Ptr[0] == 0x4C && Ptr[1] == 0x8B && Ptr[2] == 0xDC)
                    && !(Ptr[0] == 0x48 && Ptr[1] == 0x8B && Ptr[2] == 0xC4))
                    continue;

                if (Skip > 0)
                {
                    Skip--;
                    continue;
                }

                InitListen = uint64_t(Ptr);
                break;
            }

            if (!InitListen)
                InitListen = Precision::WalkBackToPrologueFromString(sRef);
        }

        if (!InitListen && VersionInfo.EngineVersion >= 5.0)
        {
            auto Hits = Precision::FindAllPatterns("4D 8B C8 4C 8B C2 33 D2 FF 90 ? ? ? ? 84 C0 75 ? 80 3D");
            InitListen = Precision::PickBest(Hits, [](uint64_t Func, uint64_t Hit) {
                int Score = 0;
                if (Precision::FuncContainsPattern(Func, "FF 90", 0x40) || Precision::FuncContains(Func, Hit, 0x200))
                    Score += 8;
                auto P = (uint8_t*)Func;
                if (P[0] == 0x4C && P[1] == 0x8B && P[2] == 0xDC)
                    Score += 6;
                return Score;
            });

            if (!InitListen)
            {
                InitListen = Precision::FindBestPattern({
                    "4C 8B DC 49 89 5B ? 49 89 73 ? 57 48 83 EC ? 48 8B BC 24",
                    "4C 8B DC 49 89 5B 08 49 89 73 10 57 48 83 EC 40 48 8B 7C 24 ? 49 8B F0 48 8B 01 48 8B D9 49 89 7B E0 45",
                });
            }
        }
        else if (!InitListen && VersionInfo.EngineVersion >= 4.27)
            InitListen = Precision::Pattern("4C 8B DC 49 89 5B 08 49 89 73 10 57 48 83 EC 50 48 8B BC 24 ? ? ? ? 49 8B F0 48 8B 01 48 8B");
        else if (!InitListen && VersionInfo.FortniteVersion == 1.91)
            InitListen = ImageBase + 0x3A5D200;

        if (!InitListen)
        {
            auto sRef = Precision::FindStringRefSmart(L"%s IpNetDriver listening on port %i");
            if (sRef)
                InitListen = Precision::WalkBackToPrologueFromString(sRef);
        }

        if (InitListen && !Precision::InText(InitListen))
            InitListen = 0;
    }

    return InitListen;
}

uint64_t FindSetWorld()
{
    static uint64_t SetWorld = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        if (VersionInfo.FortniteVersion <= 13.20)
        {
            if (auto SRef = Precision::FindStringRefSmart(L"AOnlineBeaconHost::InitHost failed"))
            {
                auto Call = Memcury::Scanner(SRef).ScanFor({ 0x48, 0x8B, 0xD0, 0xE8 }, false).Get();
                if (Call)
                {
                    auto Target = Memcury::Scanner(Call).RelativeOffset(4).Get();
                    if (Target && Precision::InText(Target))
                    {
                        if (auto Resolved = Precision::ResolveFuncStart(Target))
                            SetWorld = Resolved;
                        else
                            SetWorld = Target;
                    }
                }
            }
            return SetWorld;
        }

        auto ScoreSetWorld = [](uint64_t Func, uint64_t) {
            int Score = 0;
            if (Precision::FuncInVft(Func, "NetDriver") || Precision::FuncInVft(Func, "IpNetDriver"))
                Score += 40;
            if (Precision::FuncContainsPattern(Func, "4C 8D B", 0x80) || Precision::FuncContainsPattern(Func, "4C 8D B9", 0x80))
                Score += 6;
            return Score;
        };

        if (VersionInfo.FortniteVersion >= 25)
        {
            std::vector<uint64_t> Hits;
            for (auto Sig : {
                     "48 8B C4 48 89 58 ? 48 89 70 ? 48 89 78 ? 4C 89 70 ? 41 57 48 83 EC ? 48 8B FA 4C 8D B1 ? ? ? ? 48 8B 91",
                     "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC ? 4C 8D B9 ? ? ? ? 48 8B FA",
                 })
            {
                auto Found = Precision::FindAllPatterns(Sig);
                Hits.insert(Hits.end(), Found.begin(), Found.end());
            }

            SetWorld = Precision::PickBest(Hits, ScoreSetWorld);

            if (!SetWorld)
            {
                if (auto NetDriver = DefaultObjImpl("NetDriver"))
                {
                    for (int i = 0x60; i < 0xA0; i++)
                    {
                        const uint64_t Cand = uint64_t(NetDriver->Vft[i]);
                        if (!Precision::InText(Cand))
                            continue;
                        if (Precision::FuncContainsPattern(Cand, "4C 8D B1", 0x60) || Precision::FuncContainsPattern(Cand, "4C 8D B9", 0x60))
                        {
                            SetWorld = Cand;
                            break;
                        }
                    }
                }
            }
        }
        else
        {
            if (VersionInfo.FortniteVersion >= 19)
            {
                auto Hits = Precision::FindAllPatterns("48 89 5C 24 ? 57 48 83 EC ? 48 8B FA 48 8B D9 48 8B 91 ? ? ? ? 48 85 D2 75");
                SetWorld = Precision::PickBest(Hits, ScoreSetWorld);
            }

            if (!SetWorld && VersionInfo.FortniteVersion > 13.20)
            {
                auto Season = (int)floor(VersionInfo.FortniteVersion);
                uint32 VftIdx = 0;
                switch (Season)
                {
                case 13:
                    VftIdx = 0x70;
                    break;
                case 18:
                    VftIdx = 0x73;
                    break;
                case 19:
                    VftIdx = 0x7a;
                    break;
                case 22:
                case 23:
                case 20:
                    VftIdx = 0x7b;
                    break;
                case 21:
                    VftIdx = 0x7c;
                    break;
                case 24:
                    VftIdx = 0x7d;
                    break;
                default:
                    if (VersionInfo.FortniteVersion >= 14 && VersionInfo.FortniteVersion <= 15.2)
                        VftIdx = 0x71;
                    else if (VersionInfo.FortniteVersion >= 15.3 && VersionInfo.FortniteVersion < 18)
                        VftIdx = 0x72;
                    break;
                }
                if (VftIdx)
                {
                    if (auto NetDriver = DefaultObjImpl("NetDriver"))
                        SetWorld = uintptr_t(NetDriver->Vft[VftIdx]);
                }
            }
        }

        if (SetWorld && !Precision::InText(SetWorld))
            SetWorld = 0;
    }

    return SetWorld;
}

uint64_t FindTickFlush()
{
    static uint64_t TickFlush = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        if (VersionInfo.EngineVersion == 4.16)
            TickFlush = Precision::Pattern("4C 8B DC 55 53 56 57 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 41 0F 29 7B");
        else if (VersionInfo.EngineVersion == 4.19)
            TickFlush = Precision::Pattern("4C 8B DC 55 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 45 0F 29 43 ? 45 0F 29 4B ? 48 8B 05 ? ? ? ? 48");
        else if (VersionInfo.EngineVersion >= 4.27 && VersionInfo.EngineVersion < 5.0)
        {
            TickFlush = Precision::Patterns({
                "48 8B C4 48 89 58 18 55 56 57 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 0F 29 70 B8 0F 29 78 A8 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 8A",
                "48 8B C4 48 89 58 18 55 56 57 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 0F 29 70 B8 0F 29 78 A8 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 44 0F",
                "48 8B C4 48 89 58 18 55 56 57 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 0F 29 70 B8 0F 29 78 A8 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 48 8B F9 48 89 4D 38 48 8D 4D 40",
            });
        }

        if (!TickFlush)
        {
            TickFlush = Precision::FromString(L"STAT_NetTickFlush", 0x1000);
            if (!TickFlush && VersionInfo.EngineVersion == 4.20)
                TickFlush = Precision::Pattern("4C 8B DC 55 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 45 0F 29 43 ? 45 0F 29 4B ? 48 8B 05 ? ? ? ? 48");
        }

        if (TickFlush && !Precision::InText(TickFlush))
            TickFlush = 0;
    }

    return TickFlush;
}

int32_t FindIsNetRelevantForVft()
{
    static int32_t IsNetRelevantForIdx = -1;

    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        auto sRef = Precision::FindStringRefSmart(L"Actor %s / %s has no root component in AActor::IsNetRelevantFor. (Make bAlwaysRelevant=true?)");

        uintptr_t IsNetRelevantFor = 0;
        for (int i = 0; i < 2048; i++)
        {
            auto Ptr = (uint8_t*)(sRef - i);

            if (*Ptr == 0x48 && *(Ptr + 1) == 0x8b && *(Ptr + 2) == 0xc4)
            {
                IsNetRelevantFor = uint64_t(Ptr);
                break;
            }
            else if (*Ptr == 0x48 && *(Ptr + 1) == 0x89 && *(Ptr + 2) == 0x5c)
            {
                IsNetRelevantFor = uint64_t(Ptr);
                break;
            }
            else if (*Ptr == 0x40 && *(Ptr + 1) == 0x55)
            {
                IsNetRelevantFor = uint64_t(Ptr);
                break;
            }
        }

        if (!IsNetRelevantFor)
            return 0;

        auto ActorObj = DefaultObjImpl("Actor");
        if (!ActorObj)
            return IsNetRelevantForIdx = 0;

        auto ActorVft = ActorObj->Vft;

        for (int i = 0; i < 500; i++)
        {
            if (ActorVft[i] == (void*)IsNetRelevantFor)
            {
                return IsNetRelevantForIdx = i;
            }
        }
        return IsNetRelevantForIdx = 0;
    }

    return IsNetRelevantForIdx;
}

uint64_t FindServerReplicateActors()
{
    static uint64_t ServerReplicateActors = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        int ServerReplicateActorsVft = 0;
        switch ((int)floor(VersionInfo.FortniteVersion))
        {
        case 3:
            if (VersionInfo.FortniteVersion >= 3.4)
                ServerReplicateActorsVft = 0x53;
            break;
        case 4:
            ServerReplicateActorsVft = 0x53;
            break;
        case 5:
            ServerReplicateActorsVft = 0x54;
            break;
        case 6:
            ServerReplicateActorsVft = 0x56;
            break;
        case 10:
        case 9:
        case 8:
        case 7:
            if (VersionInfo.FortniteVersion >= 7.40 && VersionInfo.FortniteVersion <= 8.40 && VersionInfo.FortniteVersion != 8.30)
                ServerReplicateActorsVft = 0x57;
            else
                ServerReplicateActorsVft = 0x56;
            break;
        case 11:
            if (VersionInfo.FortniteVersion >= 11 && VersionInfo.FortniteVersion <= 11.10)
                ServerReplicateActorsVft = 0x57;
            else if (VersionInfo.FortniteVersion == 11.30 || VersionInfo.FortniteVersion == 11.31)
                ServerReplicateActorsVft = 0x59;
            else
                ServerReplicateActorsVft = 0x5a;
            break;
        case 12:
        case 13:
            ServerReplicateActorsVft = 0x5d;
            break;
        case 18:
        case 17:
        case 16:
        case 15:
        case 14:
            if (VersionInfo.FortniteVersion <= 15.2)
                ServerReplicateActorsVft = 0x5e;
            else
                ServerReplicateActorsVft = 0x5f;
            break;
        case 19:
            if (VersionInfo.FortniteVersion >= 19.2)
                ServerReplicateActorsVft = 0x65;
            else
                ServerReplicateActorsVft = 0x66;
            break;
        }
        if (ServerReplicateActorsVft)
        {
            if (auto ReplicationGraph = DefaultObjImpl("FortReplicationGraph"))
                ServerReplicateActors = uint64_t(ReplicationGraph->Vft[ServerReplicateActorsVft]);
        }
    }
    return ServerReplicateActors;
}

uint64_t FindSendRequestNow()
{
    static uint64_t SendRequestNow = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        auto sRef = Precision::FindStringRefSmart(L"MCP-Profile: Dispatching request to %s");
        if (!sRef)
            sRef = Precision::FindStringRefSmart(L"MCP-Profile: Dispatching request to %s - ContextCredentials: %s");

        if (!sRef)
            return 0;

        SendRequestNow = Precision::WalkBackToPrologueFromString(sRef);
        if (SendRequestNow && !Precision::InText(SendRequestNow))
            SendRequestNow = 0;
    }

    return SendRequestNow;
}

uint64 FindGetMaxTickRate()
{
    static uint64_t GetMaxTickRate = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        if (VersionInfo.EngineVersion >= 5.0)
        {
            GetMaxTickRate = Precision::Patterns({
                "48 8B C4 48 89 58 ? 48 89 68 ? 48 89 70 ? 57 41 55 41 56 48 83 EC ? 0F 29 70 ? 48 8B D9 0F 29",
                "40 53 48 83 EC 50 0F 29 74 24 ? 48 8B D9 0F 29 7C 24 ? 0F 28 F9 44 0F 29",
                "48 8B C4 48 89 58 ? 48 89 68 ? 48 89 70 ? 57 41 54 41 56 48 83 EC ? 0F 29 70 ? 48 8B D9",
            });
            return GetMaxTickRate;
        }

        if (VersionInfo.EngineVersion >= 4.27)
            return GetMaxTickRate = Precision::Pattern("40 53 48 83 EC 60 0F 29 74 24 ? 48 8B D9 0F 29 7C 24 ? 0F 28");

        GetMaxTickRate = Precision::FromString(L"Hitching by request!", 400);
    }

    return GetMaxTickRate;
}

uint64_t FindGiveAbility()
{
    static uint64_t GiveAbility = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        if (VersionInfo.EngineVersion <= 4.20)
            return GiveAbility = Precision::Pattern("48 89 5C 24 ? 56 57 41 56 48 83 EC 20 83 B9");
        else if (VersionInfo.EngineVersion == 4.21)
            return GiveAbility = Precision::Pattern("48 89 5C 24 ? 48 89 6C 24 ? 48 89 7C 24 ? 41 56 48 83 EC 20 83 B9 ? ? ? ? ? 49 8B E8 4C 8B F2");
        else if (VersionInfo.EngineVersion >= 5.3)
            return GiveAbility = Precision::Pattern("40 55 53 56 57 41 54 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 49 8B 40 ? 45 33 E4");
        else if (VersionInfo.EngineVersion >= 5.0)
        {
            return GiveAbility = Precision::Patterns({
                "48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 56 48 83 EC 20 8B 81 ? ? ? ? 49 8B E8 4C",
                "48 89 5C 24 ? 55 56 57 41 56 41 57 48 8B EC 48 83 EC ? 49 8B 40",
                "48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 56 48 83 EC 30 49 8B 40 10 45 33 F6 49 8B E8 48 8B F2 48 8B",
            });
        }

        auto sRef = Precision::FindStringRefSmart(L"GiveAbilityAndActivateOnce called on ability %s on the client, not allowed!", 1);
        if (!sRef)
            sRef = Precision::FindStringRefSmart(L"GiveAbilityAndActivateOnce called on ability %s on the client, not allowed!");
        if (sRef)
        {
            auto Call = Memcury::Scanner(sRef).ScanFor({ 0xE8 }).Get();
            if (Call)
                GiveAbility = Memcury::Scanner(Call).RelativeOffset(1).Get();
            if (GiveAbility)
                GiveAbility = Precision::ResolveFuncStart(GiveAbility);
        }
    }

    return GiveAbility;
}

uint64_t FindConstructAbilitySpec()
{
    static uint64_t ConstructAbilitySpec = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        if (VersionInfo.EngineVersion >= 4.20 && VersionInfo.EngineVersion <= 4.24)
            ConstructAbilitySpec = Precision::Pattern("80 61 29 F8 48 8B 44 24 ?");
        else if (VersionInfo.EngineVersion == 4.25)
            ConstructAbilitySpec = Precision::Patterns({
                "48 8B 44 24 ? 80 61 29 F8 80 61 31 FE 48 89 41 20 33 C0 89 41",
                "80 61 29 F8 48 8B 44 24 ?",
            });
        else if (VersionInfo.EngineVersion == 4.26)
            ConstructAbilitySpec = Precision::Patterns({
                "80 61 31 FE 0F 57 C0 80 61 29 F0 48 8B 44 24 ? 48",
                "48 8B 44 24 ? 80 61",
            });
        else if (VersionInfo.EngineVersion == 4.27)
            ConstructAbilitySpec = Precision::Pattern("80 61 31 FE 41 83 C9 FF 80 61 29 F0 48 8B 44 24 ? 48 89 41");
        else if (VersionInfo.EngineVersion == 5.0)
            ConstructAbilitySpec = Precision::Pattern("4C 8B C9 48 8B 44 24 ? 83 C9 FF 41 80 61 ? ? 41 80 61 ? ? 49 89 41 20 33 C0 41 88 41 30 49 89 41");
        else if (VersionInfo.EngineVersion >= 5.4)
            ConstructAbilitySpec = Precision::Patterns({
                "48 8B C4 48 89 58 ? 48 89 68 ? 48 89 70 ? 48 89 78 ? 41 56 48 83 EC ? 41 83 CE ? 33 ED 40 38 2D ? ? ? ? 41 8B F8",
                "48 8B C4 48 89 58 ? 48 89 68 ? 48 89 70 ? 48 89 78 ? 41 56 48 83 EC ? 41 83 CE",
            });
        else if (VersionInfo.EngineVersion >= 5.1)
            ConstructAbilitySpec = Precision::Patterns({
                "48 8B C4 48 89 58 ? 48 89 68 ? 48 89 70 ? 48 89 78 ? 41 56 48 83 EC ? 48 8B 44 24 ? 41 83 CE",
                "48 8B C4 48 89 58 ? 48 89 68 ? 48 89 70 ? 44 89 48 ? 57 48 83 EC ? 48 8B 44 24",
            });
    }

    return ConstructAbilitySpec;
}

uint64_t FindInternalTryActivateAbility()
{
    static uint64_t InternalTryActivateAbility = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        auto sRef = Precision::FindStringRefSmart(L"InternalTryActivateAbility called with invalid Handle! ASC: %s. AvatarActor: %s");
        if (!sRef)
            return InternalTryActivateAbility;

        if (auto Resolved = Precision::WalkBackToPrologueFromString(sRef, 1000))
            return InternalTryActivateAbility = Resolved;

        for (int i = 0; i < 1000; i++)
        {
            auto P = (uint8_t*)(sRef - i);
            if (P[0] == 0x48 && P[1] == 0x8B && P[2] == 0xC4)
                return InternalTryActivateAbility = sRef - i;
            if (P[0] == 0x4C && P[1] == 0x89 && P[2] == 0x4C)
                return InternalTryActivateAbility = sRef - i;
            if (P[0] == 0x48 && P[1] == 0x89 && P[2] == 0x5C)
                return InternalTryActivateAbility = sRef - i;
        }
    }

    return InternalTryActivateAbility;
}

uint64 FindApplyCharacterCustomization()
{
    static uint64_t ApplyCharacterCustomization = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        if (VersionInfo.FortniteVersion == 17.50)
            return ApplyCharacterCustomization = Precision::Pattern("48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 80 B9 ? ? ? ? ? 4C 8B EA");
        else if (VersionInfo.FortniteVersion >= 24)
        {
            return ApplyCharacterCustomization = Precision::Patterns({
                "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 80 B9 ? ? ? ? ? 48 8B F1",
                "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 80 B9 ? ? ? ? ? 48 8B C2",
                "48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 55 41 54 41 55 41 56 41 57 48 8B EC 48 81 EC ? ? ? ? 80 B9",
            });
        }
        else if (std::floor(VersionInfo.FortniteVersion) == 22)
            return ApplyCharacterCustomization = Precision::Pattern("48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8B EC 48 81 EC ? ? ? ? 80 B9");

        auto sRef = Precision::FindStringRefSmart(
            L"AFortPlayerState::ApplyCharacterCustomization - Failed initialization, using default parts. Player Controller: %s PlayerState: %s, HeroId: %s");

        if (!sRef)
            return 0;

        if (auto Resolved = Precision::WalkBackToPrologueFromString(sRef, 7000))
            return ApplyCharacterCustomization = Resolved;

        ApplyCharacterCustomization = Precision::Pattern("48 8B C4 48 89 50 10 55 57 48 8D 68 A1 48 81 EC ? ? ? ? 80 B9");
    }

    return ApplyCharacterCustomization;
}

uint64 FindHandlePostSafeZonePhaseChanged()
{
    static uint64_t HandlePostSafeZonePhaseChanged = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        if (VersionInfo.EngineVersion == 4.16)
            return HandlePostSafeZonePhaseChanged = Precision::Pattern("48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B B9 ? ? ? ? 33 DB 0F 29 74 24");
        else if (VersionInfo.EngineVersion == 4.19)
            return HandlePostSafeZonePhaseChanged = Precision::Pattern("48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 70 48 8B B9 ? ? ? ? 33 DB 0F 29 74 24 ? 48 8B F1 48 85 FF 74 2C E8");
        else if (VersionInfo.EngineVersion == 4.20)
        {
            auto Hits = Precision::FindAllPatterns("E8 ? ? ? ? EB 31 80 B9 ? ? ? ? ?");
            for (auto Hit : Hits)
            {
                auto Target = Memcury::Scanner(Hit).RelativeOffset(1).Get();
                if (Precision::InText(Target))
                    return HandlePostSafeZonePhaseChanged = Precision::ResolveFuncStart(Target);
            }
            return 0;
        }
        else if (VersionInfo.FortniteVersion >= 7 && VersionInfo.FortniteVersion <= 8)
        {
            auto Hits = Precision::FindAllPatterns("E9 ? ? ? ? 48 8B C1 40 38 B9");
            for (auto Hit : Hits)
            {
                auto Target = Memcury::Scanner(Hit).RelativeOffset(1).Get();
                if (Precision::InText(Target))
                    return HandlePostSafeZonePhaseChanged = Precision::ResolveFuncStart(Target);
            }
            return 0;
        }
        else if (VersionInfo.EngineVersion == 4.23)
        {
            auto Hits = Precision::FindAllPatterns("E8 ? ? ? ? EB 42 80 BA");
            for (auto Hit : Hits)
            {
                auto Target = Memcury::Scanner(Hit).RelativeOffset(1).Get();
                if (Precision::InText(Target))
                    return HandlePostSafeZonePhaseChanged = Precision::ResolveFuncStart(Target);
            }
            return 0;
        }

        auto sRef = Precision::FindStringRefSmart(L"FortGameModeAthena: No MegaStorm on SafeZone[%d].  GridCellThickness is less than 1.0.");
        if (!sRef)
            return 0;

        return HandlePostSafeZonePhaseChanged = Precision::WalkBackToPrologueFromString(sRef, 15000);
    }

    return HandlePostSafeZonePhaseChanged;
}

uint64 FindSpawnLoot()
{
    static uint64 SpawnLoot = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        auto sRef = Precision::FindStringRefSmart(L"ABuildingContainer::SpawnLoot() called on %s (%s)...");

        if (!sRef)
            sRef = Precision::FindStringRefSmart(L"ABuildingContainer::SpawnLoot() called on %s (%s)");

        if (!sRef)
            sRef = Precision::FindStringRefSmart(L"ABuildingContainer::SpawnLoot() >>> START called on %s (%s)");

        if (!sRef)
            return 0;

        for (int i = 0; i < 0x1000; i++)
        {
            if (*(uint8_t*)(sRef - i) == 0x40 && (*(uint8_t*)(sRef - i + 1) == 0x53 || *(uint8_t*)(sRef - i + 1) == 0x55))
                return SpawnLoot = sRef - i;
            else if (*(uint8_t*)(sRef - i) == 0x48 && *(uint8_t*)(sRef - i + 1) == 0x89 && *(uint8_t*)(sRef - i + 2) == 0x5C)
                return SpawnLoot = sRef - i;
            else if (*(uint8_t*)(sRef - i) == 0x48 && *(uint8_t*)(sRef - i + 1) == 0x8B && *(uint8_t*)(sRef - i + 2) == 0xC4)
                return SpawnLoot = sRef - i;
        }
    }

    return SpawnLoot;
}

uint64_t FindFinishedTargetSpline()
{
    static uint64 FinishedTargetSpline = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        if (VersionInfo.EngineVersion == 4.16 || VersionInfo.EngineVersion == 4.19)
            return FinishedTargetSpline = Precision::Pattern("4C 8B DC 53 55 56 48 83 EC 60 48 8B F1 48 8B 89 ? ? ? ? 48 85 C9");
        else if (VersionInfo.EngineVersion == 4.20)
            return FinishedTargetSpline = Precision::Patterns({
                "4C 8B DC 53 55 56 48 83 EC 60 48 8B F1 48 8B 89",
                "48 89 5C 24 ? 57 48 83 EC 20 48 8B D9 48 8B 89 ? ? ? ? 48 85 C9 74 20 48 8D 44 24",
            });
        else if (VersionInfo.EngineVersion == 4.21)
            return FinishedTargetSpline = Precision::Patterns({
                "40 53 56 48 83 EC 38 4C 89 6C 24 ? 48 8B F1 4C 8B A9",
                "40 53 56 57 48 83 EC 30 4C 89 6C 24 ? 48 8B F1 4C 8B A9 ? ? ? ? 4D 85 ED 0F 84",
            });
        else if (VersionInfo.EngineVersion == 4.22)
            return FinishedTargetSpline = Precision::Pattern("40 53 56 57 48 83 EC 30 4C 89 6C 24 ? 48 8B F1 4C 8B A9 ? ? ? ? 4D 85 ED 0F 84");
        else if (VersionInfo.EngineVersion >= 4.23 && VersionInfo.EngineVersion <= 4.26)
            return FinishedTargetSpline = Precision::Pattern("40 53 56 48 83 EC 38 4C 89 6C 24 ? 48 8B F1 4C 8B A9 ? ? ? ? 4D 85 ED");
        else if (VersionInfo.EngineVersion == 4.27)
            return FinishedTargetSpline = Precision::Patterns({
                "48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 54 41 56 41 57 48 83 EC 20 48 8B B1 ? ? ? ? 48 8B D9 48 85 F6",
                "48 89 5C 24 ? 48 89 74 24 ? 55 57 41 54 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 48 8B B9 ? ? ? ? 48 8B D9 48 85 FF 74 16 48 89",
                "48 8B C4 48 89 58 10 48 89 68 18 57 48 83 EC 20 48 8B D9 48 8B 89 ? ? ? ? 48 85",
            });
        else if (VersionInfo.EngineVersion == 5.0)
            return FinishedTargetSpline = Precision::Patterns({
                "48 89 5C 24 ? 48 89 74 24 ? 55 57 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 48 8B B9",
                "48 89 5C 24 ? 48 89 74 24 ? 55 57 41 54 48 8D AC 24 ? ? ? ? 48 81 EC A0 01 00 00",
                "48 8B C4 48 89 58 10 48 89 70 18 48 89 78 20 55 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 48 8B B9 ? ? ? ? 45 33 E4 48 8B D9 48 85 FF 74 0F",
                "48 8B C4 48 89 58 10 48 89 70 18 48 89 78 20 55 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 48 8B B9 ? ? ? ? 48 8B D9 48 85 FF 0F 84",
                "48 8B C4 48 89 58 10 48 89 70 18 48 89 78 20 55 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 44 8B 89 ? ? ? ? 45 33 ED",
            });
        else if (VersionInfo.EngineVersion == 5.1)
            FinishedTargetSpline = Precision::Patterns({
                "48 8B C4 48 89 58 ? 48 89 70 ? 48 89 78 ? 55 41 55 41 56 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 44 8B 91",
                "48 8B C4 48 89 58 ? 48 89 70 ? 48 89 78 ? 55 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 44 8B 81 ? ? ? ? 48 8B F9",
                "48 89 5C ?? ?? 48 89 74 ?? ?? 55 57 41 55 41 56 41 57 48 8D AC ?? ?? ?? ?? ?? 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 ?? ?? ?? ?? 44 8B 91 ?? ?? ?? ??",
                "48 89 5C 24 ? 48 89 74 24 ? 55 57 41 56 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 44 8B 81",
                "48 89 5C 24 ? 48 89 74 24 ? 55 57 41 56 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 44 8B 89",
                "48 8B C4 48 89 58 ? 48 89 70 ? 48 89 78 ? 55 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 44 8B 89 ? ? ? ? 45 33 ED",
            });
        else if (VersionInfo.EngineVersion == 5.2)
            FinishedTargetSpline = Precision::Pattern("48 8B C4 48 89 58 ? 48 89 70 ? 48 89 78 ? 55 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 44 8B 81 ? ? ? ? 48 8B D9 BE");
        else if (VersionInfo.EngineVersion >= 5.3)
            FinishedTargetSpline = Precision::Patterns({
                "48 8B C4 48 89 58 ? 48 89 70 ? 48 89 78 ? 55 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 4C 8B E1 48 89 4C 24 ? 48 81 C1",
                "48 8B C4 48 89 58 ? 48 89 70 ? 48 89 78 ? 55 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 4C 8B F9 48 89 4C 24 ? 48 81 C1",
                "48 8B C4 48 89 58 ? 48 89 70 ? 48 89 78 ? 55 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 48 8B F9 48 89 4C 24 ? 48 81 C1 ? ? ? ? E8",
                "48 8B C4 48 89 58 ? 48 89 70 ? 48 89 78 ? 55 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 4C 8B F1 48 89 4C 24 ? 48 81 C1 ? ? ? ? E8",
            });
    }

    return FinishedTargetSpline;
}

uint64_t FindPickTeam()
{
    static uint64_t PickTeam = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        if (VersionInfo.EngineVersion == 4.26)
        {
            PickTeam = Precision::Patterns({
                "88 54 24 10 53 56 41 54 41 55 41 56 48 83 EC 60 4C 8B A1",
                "88 54 24 10 53 55 56 41 55 41 ? 48 83 EC 70 48",
            });
            if (PickTeam)
                return PickTeam;
        }
        else if (VersionInfo.FortniteVersion == 7.20 || VersionInfo.FortniteVersion == 7.30)
            return PickTeam = Precision::Pattern("89 54 24 10 53 56 41 54 41 55 41 56 48 81 EC");

        auto sRef = Precision::FindStringRefSmart(L"PickTeam for [%s] used beacon value [%d]");
        if (!sRef)
            sRef = Precision::FindStringRefSmart(L"PickTeam for [%s] used beacon value [%s]");

        if (sRef)
        {
            PickTeam = Precision::WalkBackToPrologueFromString(sRef);
            if (!PickTeam)
            {
                PickTeam = Memcury::Scanner(sRef)
                               .ScanFor(VersionInfo.FortniteVersion <= 4.1 ? std::vector<uint8_t>{ 0x48, 0x89, 0x6C }
                                                                          : (VersionInfo.FortniteVersion >= 16 ? std::vector<uint8_t>{ 0x48, 0x89, 0x5C } : std::vector<uint8_t>{ 0x40, 0x55 }),
                                   false)
                               .Get();
            }
        }
    }

    return PickTeam;
}

uint64_t FindCantBuild()
{
    static uint64_t CantBuild = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        CantBuild = Precision::Patterns({
            "48 89 5C 24 10 48 89 6C 24 18 48 89 74 24 20 41 56 48 83 EC ? 49 8B E9 4D 8B F0",
            "48 89 54 24 ? 55 56 41 56 48 83 EC 50",
            "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC 60 4D 8B F1 4D 8B F8",
            "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC 60 49 8B E9 4D 8B F8 48 8B DA 48 8B F9 BE ? ? ? ? 48",
            "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC 70 49 8B E9 4D 8B F8 48 8B DA 48 8B F9",
            "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC ? 48 8B 1A 4D 8B F1",
        });
    }

    return CantBuild;
}

uint64_t FindReplaceBuildingActor()
{
    static uint64_t ReplaceBuildingActor = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        auto sRef = Precision::FindStringRefSmart(L"STAT_Fort_BuildingSMActorReplaceBuildingActor");

        if (!sRef)
            return ReplaceBuildingActor = Precision::Pattern("4C 89 44 24 ? 55 56 57 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 45");

        return ReplaceBuildingActor = Memcury::Scanner(sRef).ScanFor(VersionInfo.EngineVersion == 4.20 || (VersionInfo.EngineVersion == 4.21 && VersionInfo.FortniteVersion < 6.30) || VersionInfo.EngineVersion >= 4.27
                                                       ? std::vector<uint8_t>{ 0x48, 0x8B, 0xC4 }
                                                       : std::vector<uint8_t>{ 0x4C, 0x8B },
                                                   false, 0, 1, 1000)
                                          .Get();
    }

    return ReplaceBuildingActor;
}

uint64_t FindKickPlayer()
{
    const bool bHadDedicatedBranch =
        VersionInfo.EngineVersion == 4.16
        || std::floor(VersionInfo.FortniteVersion) == 18
        || std::floor(VersionInfo.FortniteVersion) == 19
        || VersionInfo.EngineVersion >= 5.0
        || (VersionInfo.FortniteVersion >= 7.00 && VersionInfo.FortniteVersion <= 15.50);

    if (VersionInfo.EngineVersion == 4.16)
    {
        if (auto pattern = Precision::Pattern("40 53 56 48 81 EC ? ? ? ? 48 8B DA 48 8B F1 E8 ? ? ? ? 48 8B 06 48 8B CE"))
            return pattern;
    }
    else if (std::floor(VersionInfo.FortniteVersion) == 18)
        return Precision::Pattern("48 8B C4 48 89 58 08 48 89 70 10 48 89 78 18 4C 89 60 20 55 41 56 41 57 48 8B EC 48 83 EC 60 48 83 65 ? ? 4C 8B F2 83 65 E8 00 4C 8B E1 83 65 EC");
    else if (std::floor(VersionInfo.FortniteVersion) == 19)
    {
        return Precision::Patterns({
            "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 45 33 E4 48 8B FA 41 8B DC",
            "48 89 5C 24 ? 55 56 57 48 8B EC 48 83 EC 60 48 8B FA 48 8B F1 E8",
        });
    }
    else if (VersionInfo.EngineVersion >= 5.4)
    {
        return Precision::Patterns({
            "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 ? 45 33 ED 48 8B FA 41 8B DD",
            "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 ? 33 DB 48 8B FA 89 5C 24",
            "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 33 FF 48 8B F2 89 7C 24",
            "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 45 33 E4 48 8B F2 41 8B FC",
            "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 ? 45 33 E4 48 8B FA 41 8B DC",
            "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 45 33 F6 48 89 4C 24 ? 45 8B FE",
        });
    }
    else if (VersionInfo.EngineVersion >= 5.0)
    {
        return Precision::Patterns({
            "48 89 5C ?? ?? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C ?? ?? 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 45 ?? 45 33 E4 48 8B FA 41 8B DC",
            "48 89 5C ?? ?? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C ?? ?? 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 45 ?? 45 33 FF 48 8B FA 41 8B DF",
            "48 89 5C ?? ?? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C ?? ?? 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 45 ?? 45 33 ED 48 8B FA 41 8B DD",
            "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 45 33 ED 48 8B FA 41 8B DD",
            "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 ? 33 DB 48 8B FA",
        });
    }
    else if (VersionInfo.FortniteVersion >= 7.00 && VersionInfo.FortniteVersion <= 15.50)
    {
        return Precision::Pattern("48 89 5C 24 08 48 89 74 24 10 57 48 83 EC ? 49 8B F0 48 8B DA 48 85 D2");
    }

    auto sRef = Precision::FindStringRefSmart(L"Validation Failure: %s. kicking %s");

    if (sRef)
        for (int i = 0; i < 2000; i++)
        {
            if (*(uint8_t*)(sRef - i) == 0x40 && *(uint8_t*)(sRef - i + 1) == 0x53)
                return sRef - i;

            else if (*(uint8_t*)(sRef - i) == 0x40 && *(uint8_t*)(sRef - i + 1) == 0x55)
                return sRef - i;
        }

    auto sRef2 = Precision::FindStringRefSmart(L"Failed to kick player");

    if (sRef2)
        for (int i = 0; i < 3000; i++)
        {
            if (*(uint8_t*)(sRef2 - i) == 0x48 && *(uint8_t*)(sRef2 - i + 1) == 0x89 && *(uint8_t*)(sRef2 - i + 2) == 0x5C)
                return sRef2 - i;

            if (VersionInfo.FortniteVersion >= 17)
                if (*(uint8_t*)(sRef2 - i) == 0x48 && *(uint8_t*)(sRef2 - i + 1) == 0x8B && *(uint8_t*)(sRef2 - i + 2) == 0xC4)
                    return sRef2 - i;
        }

    if (!bHadDedicatedBranch)
        return Precision::Pattern("40 53 41 56 48 81 EC ? ? ? ? 48 8B 01 48 8B DA 4C 8B F1 FF 90");

    return 0;
}

uint64_t FindEncryptionPatch()
{
    static uint64_t EncryptionPatch = 0;

    if (EncryptionPatch == 0)
    {
        static const char* Sigs[] = {
            "83 BD ? ? ? ? 01 7F 18 49 8D 4D D8 48 8B D6 E8 ? ? ? ? 48",
            "83 BD ? ? ? ? ? 7F 18 49 8D 4D D8 48 8B D7 E8",
            "83 7D 88 01 7F 0D 48 8B CE E8",
            "83 7C 24 ?? 01 7F 0D 48 8B CF E8",
            "83 7C 24 ? ? 7F 0D 49 8B CE",
            "83 7C 24 ? ? 7F 0D 48 8B CE",
            "83 7D ? ? 7F 14 48 8D 8B",
        };

        uint64_t EncryptionPatchPoint = 0;
        for (auto Sig : Sigs)
        {
            auto Hits = Precision::FindAllPatterns(Sig);
            if (!Hits.empty())
            {
                EncryptionPatchPoint = Hits[0];
                break;
            }
        }

        if (EncryptionPatchPoint)
            for (int i = 0; i < 9; i++)
            {
                if (*(uint8_t*)(EncryptionPatchPoint + i) == 0x7F)
                    EncryptionPatch = EncryptionPatchPoint + i;
            }
    }

    return EncryptionPatch;
}

uint64_t FindRemoveInventoryItem()
{
    static uint64_t RemoveInventoryItem = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        std::vector<uint8_t> funcStart =
            VersionInfo.EngineVersion == 4.16
                ? std::vector<uint8_t>{ 0x44, 0x88, 0x4C }
                : (VersionInfo.FortniteVersion >= 16 && (VersionInfo.FortniteVersion < 20 || VersionInfo.FortniteVersion >= 22) ? std::vector<uint8_t>{ 0x48, 0x8B, 0xC4 } : std::vector<uint8_t>{ 0x48, 0x89, 0x5C });

        auto sRef = FindNameRef(L"ServerRemoveInventoryItem", 0, false);
        uintptr_t uFuncCall = 0;
        for (int i = 0; i < 2000; i++)
        {
            if (VersionInfo.EngineVersion == 4.16)
            {
                if (*(uint8_t*)(sRef - i) == 0x44 && *(uint8_t*)(sRef - i + 1) == 0x88 && *(uint8_t*)(sRef - i + 2) == 0x4C)
                {
                    uFuncCall = sRef - i;
                    break;
                }
            }
            else
            {
                if (*(uint8_t*)(sRef - i) == 0x48 && *(uint8_t*)(sRef - i + 1) == 0x89 && *(uint8_t*)(sRef - i + 2) == 0x5C)
                {
                    uFuncCall = sRef - i;
                    break;
                }
                else if (*(uint8_t*)(sRef - i) == 0x48 && *(uint8_t*)(sRef - i + 1) == 0x8B && *(uint8_t*)(sRef - i + 2) == 0xC4)
                {
                    uFuncCall = sRef - i;
                    break;
                }
            }
        }

        auto ServerRemoveInventoryItemCall = Memcury::Scanner::FindPointerRef((PVOID)uFuncCall, 0, true);

        for (int i = 0; i < 400; i++)
        {
            if (*(uint8_t*)(ServerRemoveInventoryItemCall.Get() - i) == 0x48 && *(uint8_t*)(ServerRemoveInventoryItemCall.Get() - i + 1) == 0x89 && *(uint8_t*)(ServerRemoveInventoryItemCall.Get() - i + 2) == 0x5C)
                return RemoveInventoryItem = ServerRemoveInventoryItemCall.Get() - i;
            else if (*(uint8_t*)(ServerRemoveInventoryItemCall.Get() - i) == 0x48 && *(uint8_t*)(ServerRemoveInventoryItemCall.Get() - i + 1) == 0x83 &&
                     *(uint8_t*)(ServerRemoveInventoryItemCall.Get() - i + 2) == 0xEC)
                return RemoveInventoryItem = ServerRemoveInventoryItemCall.Get() - i;
        }
    }

    return RemoveInventoryItem;
}

uint64_t FindRemoveInventoryStateValue()
{
    static uint64_t RemoveInventoryStateValue = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        std::vector<uint8_t> funcStart =
            VersionInfo.EngineVersion == 4.16
                ? std::vector<uint8_t>{ 0x44, 0x88, 0x4C }
                : (VersionInfo.FortniteVersion >= 16 && (VersionInfo.FortniteVersion < 20 || VersionInfo.FortniteVersion >= 22) ? std::vector<uint8_t>{ 0x48, 0x8B, 0xC4 } : std::vector<uint8_t>{ 0x48, 0x89, 0x5C });

        auto sRef = FindNameRef(L"ServerRemoveInventoryStateValue", 0, false);
        for (int i = 0; i < 2000; i++)
        {
            if (VersionInfo.EngineVersion == 4.16)
            {
                if (*(uint8_t*)(sRef - i) == 0x44 && *(uint8_t*)(sRef - i + 1) == 0x88 && *(uint8_t*)(sRef - i + 2) == 0x4C)
                {
                    RemoveInventoryStateValue = sRef - i;
                    break;
                }
            }
            else
            {
                if (*(uint8_t*)(sRef - i) == 0x48 && *(uint8_t*)(sRef - i + 1) == 0x89 && *(uint8_t*)(sRef - i + 2) == 0x5C)
                {
                    RemoveInventoryStateValue = sRef - i;
                    break;
                }
                else if (*(uint8_t*)(sRef - i) == 0x48 && *(uint8_t*)(sRef - i + 1) == 0x8B && *(uint8_t*)(sRef - i + 2) == 0xC4)
                {
                    RemoveInventoryStateValue = sRef - i;
                    break;
                }
            }
        }
    }

    return RemoveInventoryStateValue;
}

uint64_t FindSetInventoryStateValue()
{
    static uint64_t SetInventoryStateValue = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        std::vector<uint8_t> funcStart =
            VersionInfo.EngineVersion == 4.16
                ? std::vector<uint8_t>{ 0x44, 0x88, 0x4C }
                : (VersionInfo.FortniteVersion >= 16 && (VersionInfo.FortniteVersion < 20 || VersionInfo.FortniteVersion >= 22) ? std::vector<uint8_t>{ 0x48, 0x8B, 0xC4 } : std::vector<uint8_t>{ 0x48, 0x89, 0x5C });

        auto sRef = FindNameRef(L"ServerSetInventoryStateValue", 0, false);
        for (int i = 0; i < 2000; i++)
        {
            if (VersionInfo.EngineVersion == 4.16)
            {
                if (*(uint8_t*)(sRef - i) == 0x44 && *(uint8_t*)(sRef - i + 1) == 0x88 && *(uint8_t*)(sRef - i + 2) == 0x4C)
                {
                    SetInventoryStateValue = sRef - i;
                    break;
                }
            }
            else
            {
                if (*(uint8_t*)(sRef - i) == 0x48 && *(uint8_t*)(sRef - i + 1) == 0x89 && *(uint8_t*)(sRef - i + 2) == 0x5C)
                {
                    SetInventoryStateValue = sRef - i;
                    break;
                }
                else if (*(uint8_t*)(sRef - i) == 0x48 && *(uint8_t*)(sRef - i + 1) == 0x8B && *(uint8_t*)(sRef - i + 2) == 0xC4)
                {
                    SetInventoryStateValue = sRef - i;
                    break;
                }
            }
        }
    }

    return SetInventoryStateValue;
}

uint64_t FindOnRep_ZiplineState()
{
    static uint64_t OnRep_ZiplineState = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        auto sRef = Precision::FindStringRefSmart(L"ZIPLINES!! Role(%s)  AFortPlayerPawn::OnRep_ZiplineState ZiplineState.bIsZiplining=%d");
        if (!sRef)
            sRef = Precision::FindStringRefSmart(L"ZIPLINES!! GetLocalRole()(%s)  AFortPlayerPawn::OnRep_ZiplineState ZiplineState.bIsZiplining=%d");
        if (!sRef)
            sRef = Precision::FindStringRefSmart(L"AFortPlayerPawn::HandleZiplineStateChanged");

        if (sRef)
        {
            for (int i = 0; i < 0x400; i++)
            {
                if (*(uint8_t*)(sRef - i) == 0x40 && *(uint8_t*)(sRef - i + 1) == 0x53)
                    return OnRep_ZiplineState = sRef - i;

                if (*(uint8_t*)(sRef - i) == 0x48 && *(uint8_t*)(sRef - i + 1) == 0x89 && *(uint8_t*)(sRef - i + 2) == 0x5C)
                    return OnRep_ZiplineState = sRef - i;

                if (*(uint8_t*)(sRef - i) == 0x48 && *(uint8_t*)(sRef - i + 1) == 0x8B && *(uint8_t*)(sRef - i + 2) == 0xC4)
                    return OnRep_ZiplineState = sRef - i;
            }
        }
    }

    return OnRep_ZiplineState;
}

uint64 FindGiveAbilityAndActivateOnce()
{
    static uint64_t GiveAbilityAndActivateOnce = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        if (VersionInfo.EngineVersion == 4.26)
        {
            return GiveAbilityAndActivateOnce = Precision::Patterns({
                "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 40 49 8B 40 10 49 8B D8 48 8B FA 48 8B F1",
                "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 40 49 8B 40 10 49",
            });
        }

        auto sRef = Precision::FindStringRefSmart(L"GiveAbilityAndActivateOnce called on ability %s on the client, not allowed!");
        if (!sRef)
            return 0;

        if (auto Resolved = Precision::WalkBackToPrologueFromString(sRef, 1000))
            return GiveAbilityAndActivateOnce = Resolved;

        return 0;
    }

    return GiveAbilityAndActivateOnce;
}

uint64_t FindClearAbility()
{
    static uint64_t ClearAbility = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        auto GiveAbilityAndActivateOnce = FindGiveAbilityAndActivateOnce();

        if (!GiveAbilityAndActivateOnce)
            return 0;

        int skip = 0;
        for (int i = 0; i < 2048; i++)
        {
            // mov rcx, (rdi|rsi)
            // call ClearAbility
            // jmp
            if ((*(uint8_t*)(GiveAbilityAndActivateOnce + i) & 0xF8) == 0x48 && *(uint8_t*)(GiveAbilityAndActivateOnce + i + 1) == 0x8B && *(uint8_t*)(GiveAbilityAndActivateOnce + i + 3) == 0xE8 &&
                (*(uint8_t*)(GiveAbilityAndActivateOnce + i + 8) == 0xE9 || *(uint8_t*)(GiveAbilityAndActivateOnce + i + 8) == 0xEB))
            {
                return ClearAbility = Memcury::Scanner(GiveAbilityAndActivateOnce + i + 3).RelativeOffset(1).Get();
            }
        }
    }

    return ClearAbility;
}

uint64 FindGameSessionPatch()
{
    auto sRef = Precision::FindStringRefSmart(L"Gamephase Step: %s");
    uint64 Beginning = 0;

    if (!sRef)
    {
        Beginning = Precision::Pattern("48 89 5C 24 ? 57 48 83 EC 20 E8 ? ? ? ? 48 8B D8 48 85 C0 0F 84 ? ? ? ? E8");

        if (!Beginning)
            return 0;
    }
    else
    {
        for (int i = 0; i < 3000; i++)
        {
            if (*(uint8_t*)(sRef - i) == 0x40 && *(uint8_t*)(sRef - i + 1) == 0x55)
            {
                Beginning = sRef - i;
                break;
            }
            else if (*(uint8_t*)(sRef - i) == 0x48 && *(uint8_t*)(sRef - i + 1) == 0x89 && *(uint8_t*)(sRef - i + 2) == 0x5C)
            {
                Beginning = sRef - i;
                break;
            }
            else if (*(uint8_t*)(sRef - i) == 0x48 && *(uint8_t*)(sRef - i + 1) == 0x8B && *(uint8_t*)(sRef - i + 2) == 0xC4)
            {
                Beginning = sRef - i;
                break;
            }
        }
    }

    if (!Beginning)
        return 0;

    for (int i = 0; i < 500; i++)
        if (*(uint8_t*)(Beginning + i) == 0x0F && *(uint8_t*)(Beginning + i + 1) == 0x84)
            return Beginning + i + 1;

    return 0;
}

uint64 FindRemoveFromAlivePlayers()
{
    static uint64 RemoveFromAlivePlayers = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        auto sRef = Precision::FindStringRefSmart(L"FortGameModeAthena: Player [%s] removed from alive players list (Team [%d]).  Player count is now [%d].  Team count is now [%d].");

        if (!sRef)
            sRef = Precision::FindStringRefSmart(L"FortGameModeAthena: Player [%s] removed from alive players list (Team [%d]).  Player count is now [%d]. PlayerBots count is now [%d]. Team count is now [%d].");

        if (!sRef)
            sRef = Precision::FindStringRefSmart(L"FortGameModeAthena::RemoveFromAlivePlayers: Player [%s] PC [%s] removed from alive players list (Team [%d]).  Player count is "
                                                   L"now [%d]. PlayerBots count is now [%d]. Team count is now [%d].");

        for (int i = 0; i < 0x1200; i++)
        {
            if (*(uint8_t*)(sRef - i) == 0x4C && *(uint8_t*)(sRef - i + 1) == 0x89 && *(uint8_t*)(sRef - i + 2) == 0x4C)
                return RemoveFromAlivePlayers = sRef - i;
            else if (*(uint8_t*)(sRef - i) == 0x48 && *(uint8_t*)(sRef - i + 1) == 0x89 && *(uint8_t*)(sRef - i + 2) == 0x54)
            {
                for (int z = 3; z < 50; z++)
                    if (*(uint8_t*)(sRef - i - z) == 0x4C && *(uint8_t*)(sRef - i - z + 1) == 0x89 && *(uint8_t*)(sRef - i - z + 2) == 0x4C)
                        return RemoveFromAlivePlayers = sRef - i - z;

                return RemoveFromAlivePlayers = sRef - i;
            }
            else if (*(uint8_t*)(sRef - i) == 0x48 && *(uint8_t*)(sRef - i + 1) == 0x8B && *(uint8_t*)(sRef - i + 2) == 0xC4)
                return RemoveFromAlivePlayers = sRef - i;
            else if (VersionInfo.EngineVersion >= 5.3 && *(uint8_t*)(sRef - i) == 0x48 && *(uint8_t*)(sRef - i + 1) == 0x89 && *(uint8_t*)(sRef - i + 2) == 0x5C)
                return RemoveFromAlivePlayers = sRef - i;
        }

        return 0;
    }

    return RemoveFromAlivePlayers;
}

uint64 FindStartAircraftPhase()
{
    static uint64_t StartAircraftPhase = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        if (VersionInfo.EngineVersion < 4.27)
        {
            auto sRef = Precision::FindStringRefSmart(L"STARTAIRCRAFT");

            if (!sRef)
                return 0;

            int numCalls = 0;

            for (int i = 0; i < 150; i++)
                if (*(uint8_t*)(sRef + i) == 0xE8)
                {
                    if (++numCalls == 2)
                        return StartAircraftPhase = Memcury::Scanner(sRef + i).RelativeOffset(1).Get();
                    else
                        i += 4;
                }
        }
        else
        {
            auto sRef = Precision::FindStringRefSmart(L"STAT_StartAircraftPhase");

            if (!sRef)
                return 0;

            for (int i = 0; i < 1000; i++)
                if (*(uint8_t*)(sRef - i) == 0x48 && *(uint8_t*)(sRef - i + 1) == 0x8B && *(uint8_t*)(sRef - i + 2) == 0xC4)
                    return StartAircraftPhase = sRef - i;
        }

        return 0;
    }

    return StartAircraftPhase;
}

uint64_t FindSetPickupItems()
{
    static uint64_t SetPickupItems = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        if (VersionInfo.EngineVersion == 4.16 || VersionInfo.EngineVersion == 4.19)
            return SetPickupItems = Precision::Pattern("48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 80 B9 ? ? ? ? ? 41 0F B6 E9");
        else if (VersionInfo.FortniteVersion <= 3.3)
            return SetPickupItems = Precision::Pattern("48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 80 B9 ? ? ? ? ? 41 0F B6 E9 49 8B F8 48 8B F1 0F 85 ? ? ? ? 48 83 7A");
        else if (VersionInfo.EngineVersion == 4.20)
            return SetPickupItems = Precision::Pattern("48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 41 56 48 83 EC 20 80 B9 ? ? ? ? ? 45 0F B6 F1 49 8B E8");
        else if (VersionInfo.EngineVersion == 4.21)
        {
            SetPickupItems = Precision::Pattern("48 89 5C 24 ? 55 57 41 57 48 83 EC 30 80 B9 ? ? ? ? ? 41 0F B6");

            if (!SetPickupItems)
                SetPickupItems = Precision::Pattern("48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 80 B9 ? ? ? ? ? 41 0F B6 E9");

            return SetPickupItems;
        }
        else if (VersionInfo.EngineVersion == 4.22)
            return SetPickupItems = Precision::Pattern("48 89 5C 24 ? 57 41 56 41 57 48 83 EC 30 80 B9 ? ? ? ? ? 45 0F B6 F1");
        else if (VersionInfo.EngineVersion == 4.23)
            return SetPickupItems = Precision::Pattern("48 89 5C 24 ? 57 41 56 41 57 48 83 EC 30 80 B9 ? ? ? ? ? 45 0F B6 F1 4D");
        else if (VersionInfo.EngineVersion == 4.24 || VersionInfo.EngineVersion == 4.25)
            return SetPickupItems = Precision::Pattern("48 89 5C 24 ? 55 57 41 57 48 83 EC ? 80 B9");
        else if (VersionInfo.EngineVersion == 4.26)
        {
            SetPickupItems = Precision::Pattern("48 89 5C 24 ? 55 57 41 57 48 83 EC ? 80 B9");

            if (!SetPickupItems)
                SetPickupItems = Precision::Pattern("48 89 5C 24 ? 56 57 41 57 48 83 EC ? 80 B9");

            return SetPickupItems;
        }
        else if (VersionInfo.EngineVersion == 4.27)
            return SetPickupItems = Precision::Pattern("48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC ? 80 B9 ? ? ? ? ? 45 8A");
        else if (VersionInfo.EngineVersion >= 5.0)
        {
            SetPickupItems = Precision::Pattern("48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC ? 80 B9 ? ? ? ? ? 45 8A F9");

            if (!SetPickupItems)
                SetPickupItems = Precision::Pattern("48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC ? 80 B9 ? ? ? ? ? 45 8A F1");
        }
    }

    return SetPickupItems;
}

uint64_t FindCallPreReplication()
{
    static uint64_t CallPreReplication = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        if (VersionInfo.EngineVersion == 4.16)
            return CallPreReplication = Precision::Pattern("48 85 D2 0F 84 ? ? ? ? 48 8B C4 55 57 41 57 48 8D 68 A1 48 81 EC");
        else if (VersionInfo.EngineVersion == 4.19)
            return CallPreReplication = Precision::Pattern("48 85 D2 0F 84 ? ? ? ? 48 8B C4 55 57 41 54 48 8D 68 A1 48 81 EC ? ? ? ? 48 89 58 08 4C");
        else if (VersionInfo.FortniteVersion >= 2.5 && VersionInfo.FortniteVersion <= 3.3)
            return CallPreReplication = Precision::Pattern("48 85 D2 0F 84 ? ? ? ? 56 41 56 48 83 EC 38 4C 8B F2");
        else if (std::floor(VersionInfo.FortniteVersion) == 20)
        {
            CallPreReplication = Precision::Pattern("48 85 D2 0F 84 ? ? ? ? 48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC 40 F6 41 58 30 48 8B EA 48 8B D9 40 B6 01");

            if (!CallPreReplication)
                CallPreReplication = Precision::Pattern("48 85 D2 0F 84 ? ? ? ? 48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC 40 F6 41 58 30 48 8B EA 48 8B D9 75");
        }
        else if (VersionInfo.FortniteVersion < 22)
        {
            CallPreReplication = Precision::Pattern("48 85 D2 0F 84 ? ? ? ? 48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC 40 F6 41 58 30 4C 8B F2");

            if (!CallPreReplication)
                CallPreReplication = Precision::Pattern("48 85 D2 0F 84 ? ? ? ? 48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC ? F6 41");
        }
        else if (VersionInfo.FortniteVersion <= 22.30)
            return CallPreReplication = Precision::Pattern("48 85 D2 0F 84 ? ? ? ? 48 8B C4 48 89 58 ? 48 89 70 ? 48 89 78 ? 4C 89 60 ? 55 41 56 41 57 48 8B EC 48 83 EC ? F6 41 ? ? 4C 8B FA 48 8B");
        else if (VersionInfo.FortniteVersion >= 22.40)
            return CallPreReplication = Precision::Pattern("48 85 D2 0F 84 ? ? ? ? 48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 55 41 56 41 57 48 8B EC 48 83 EC ? F6 41");
    }

    return CallPreReplication;
}

uint64_t FindSendClientAdjustment()
{
    static uint64_t SendClientAdjustment = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        if (VersionInfo.EngineVersion >= 5.4)
        {
            SendClientAdjustment = Precision::Pattern("48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B F9 E8 ? ? ? ? 48 8B D8 48 85 C0 74 ? 80 78");

            if (!SendClientAdjustment)
                SendClientAdjustment = Precision::Pattern("48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 8B 91 ? ? ? ? 48 8B D9 83 FA");
        }
        else if (VersionInfo.FortniteVersion >= 25.00)
        {
            SendClientAdjustment = Precision::Pattern("48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B D9 E8 ? ? ? ? 80 B8 ? ? ? ? ? 75 ? 8B 93");

            if (!SendClientAdjustment)
                SendClientAdjustment = Precision::Pattern("48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 83 3D ? ? ? ? ? 48 8B D9 75");
        }
        else if (VersionInfo.FortniteVersion >= 23.00)
        {
            SendClientAdjustment = Precision::Pattern("48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 83 3D ? ? ? ? ? 48 8B D9 75");

            if (!SendClientAdjustment)
                SendClientAdjustment = Precision::Pattern("48 8B C4 48 89 58 ? 48 89 68 ? 48 89 70 ? 48 89 78 ? 41 56 48 83 EC ? 83 3D ? ? ? ? ? 48 8B F1");
        }
        else if (VersionInfo.FortniteVersion >= 20.00)
            SendClientAdjustment = Precision::Pattern("48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 8B 91 ? ? ? ? 48 8B D9 83 FA");
        else
            SendClientAdjustment = Precision::Pattern("40 53 48 83 EC 20 48 8B 99 ? ? ? ? 48 39 99 ? ? ? ? 74 0A 48 83 B9");
    }

    return SendClientAdjustment;
}

uint64 FindSetChannelActor()
{
    static uint64_t SetChannelActor = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        if (VersionInfo.EngineVersion == 4.16)
            return SetChannelActor = Precision::Pattern("4C 8B DC 55 53 57 41 54 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 45 33");
        else if (VersionInfo.FortniteVersion == 3.3)
            return SetChannelActor = Precision::Pattern("48 8B C4 55 53 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 48 89 70 10 48 8B D9 48 89 78 18 48 8D 35");
        else if (VersionInfo.EngineVersion >= 4.19 && VersionInfo.FortniteVersion < 3.3)
        {
            SetChannelActor = Precision::Pattern("48 8B C4 55 53 57 41 54 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 45 33 E4 48 89 70");

            if (!SetChannelActor)
                return SetChannelActor = Precision::Pattern("48 8B C4 55 53 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 48 89 70 E8 48 8B D9");
        }
        else if (std::floor(VersionInfo.FortniteVersion) == 20)
            return SetChannelActor = Precision::Pattern("40 55 53 56 57 41 54 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 45 33 E4 48 8D 3D ? ? ? ? 44 89 A5");
        else if (VersionInfo.FortniteVersion >= 27)
            return SetChannelActor = Precision::Pattern("48 89 5C 24 ? 48 89 74 24 ? 55 57 41 54 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 45 33 FF 48 8D 35");
        else if (VersionInfo.FortniteVersion >= 21)
        {
            SetChannelActor = Precision::Pattern("48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 33 FF 4C 8D 35 ? ? ? ? 89 BD");

            if (!SetChannelActor)
                SetChannelActor = Precision::Pattern("48 89 5C 24 ? 55 56 57 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 45 33 F6");

            if (!SetChannelActor)
                SetChannelActor = Precision::Pattern("48 8B C4 48 89 58 10 48 89 70 18 48 89 78 20 55 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 45 33 "
                                                                "ED 48 8D 35 ? ? ? ? 44 89 AD ? ? ? ? 48 8B D9 48 8B 41 28 45 8B E0 48 8B FA 45 8B");

            if (!SetChannelActor)
                SetChannelActor = Precision::Pattern("48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 33 F6 4C 8D 3D");

            if (!SetChannelActor)
                SetChannelActor = Precision::Pattern("48 89 5C 24 ? 48 89 74 24 ? 55 57 41 54 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 45 33 FF");
        }
    }

    return SetChannelActor;
}

uint64 FindSetChannelActorForDestroy()
{
    static uint64_t SetChannelActorForDestroy = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        auto sRef = Precision::FindStringRefSmart(L"SetChannelActorForDestroy: Channel %d. NetGUID <%s> Path: %s. Bits: %d");

        if (!sRef)
            return SetChannelActorForDestroy = 0;

        for (int i = 0; i < 2000; i++)
        {
            if (*(uint8_t*)(sRef - i) == 0x40 && *(uint8_t*)(sRef - i + 1) == 0x55)
                return SetChannelActorForDestroy = sRef - i;
        }
    }

    return SetChannelActorForDestroy;
}

uint64 FindSendDestructionInfo()
{
    static uint64_t SendDestructionInfo = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        auto sRef = Precision::FindStringRefSmart(L"STAT_NetSendDestructionInfo");

        if (!sRef)
            return SendDestructionInfo = 0;

        for (int i = 0; i < 2000; i++)
        {
            if (*(uint8_t*)(sRef - i) == 0x48 && *(uint8_t*)(sRef - i + 1) == 0x89 && *(uint8_t*)(sRef - i + 2) == 0x4c)
            {
                if (*(uint8_t*)(sRef - i - 5) == 0x48 && *(uint8_t*)(sRef - i - 4) == 0x89 && *(uint8_t*)(sRef - i - 3) == 0x5c)
                    i += 5;

                return SendDestructionInfo = sRef - i;
            }
        }
    }

    return SendDestructionInfo;
}

uint64 FindCreateChannel()
{
    static uint64_t CreateChannel = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        if (VersionInfo.FortniteVersion <= 3.3)
            return CreateChannel = Precision::Pattern("40 56 57 41 54 41 55 41 57 48 83 EC 60 48 8B 01 41 8B F9 45 0F B6 E0");
        else if (VersionInfo.FortniteVersion >= 20)
        {
            auto sRef = Precision::FindStringRefSmart(L"STAT_NetConnection_CreateChannelByName");

            if (!sRef)
                return CreateChannel = 0;

            for (int i = 0; i < 2000; i++)
            {
                if (*(uint8_t*)(sRef - i) == 0x48 && *(uint8_t*)(sRef - i + 1) == 0x89 && *(uint8_t*)(sRef - i + 2) == 0x5c)
                    return CreateChannel = sRef - i;
                else if (*(uint8_t*)(sRef - i) == 0x40 && *(uint8_t*)(sRef - i + 1) == 0x55)
                    return CreateChannel = sRef - i;
            }
        }
    }

    return CreateChannel;
}

uint64 FindReplicateActor()
{
    static uint64_t ReplicateActor = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        if (VersionInfo.EngineVersion == 4.16)
            return ReplicateActor = Precision::Pattern("40 55 53 57 41 56 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8D 59 68 4C 8B F1 48 8B");
        else if (VersionInfo.FortniteVersion == 3.3)
            return ReplicateActor = Precision::Pattern("48 8B C4 55 53 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 0F 29 70 A8 0F 29 78 98 48 89 70 E8 4C");
        else if (VersionInfo.EngineVersion >= 4.19 && VersionInfo.FortniteVersion <= 3.2)
        {
            ReplicateActor = Precision::Pattern("40 55 56 57 41 54 41 55 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 4C");

            if (!ReplicateActor)
                ReplicateActor = Precision::Pattern("40 55 56 41 54 41 55 41 56 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 4C 8B E9 48 8B 49 68 48");
        }
        else if (VersionInfo.FortniteVersion >= 20)
        {
            auto sRef = Precision::FindStringRefSmart(L"STAT_NetReplicateActorTime");

            for (int i = 0; i < 2000; i++)
            {
                if (*(uint8_t*)(sRef - i) == 0x40 && *(uint8_t*)(sRef - i + 1) == 0x55)
                    return ReplicateActor = sRef - i;
                else if (*(uint8_t*)(sRef - i) == 0x48 && *(uint8_t*)(sRef - i + 1) == 0x8B && *(uint8_t*)(sRef - i + 2) == 0xC4)
                    return ReplicateActor = sRef - i;
            }
        }
    }

    return ReplicateActor;
}

uint64 FindCloseActorChannel()
{
    static uint64_t CloseActorChannel = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        auto sRef = Precision::FindStringRefSmart(L"UActorChannel::Close: ChIndex: %d, Actor: %s");

        if (!sRef)
            sRef = Precision::FindStringRefSmart(L"UActorChannel::Close: ChIndex: %d, Actor: %s, Reason: %s");

        if (!sRef)
            return 0;

        for (int i = 0; i < 2000; i++)
        {
            if (*(uint8_t*)(sRef - i) == 0x48 && *(uint8_t*)(sRef - i + 1) == 0x89 && *(uint8_t*)(sRef - i + 2) == 0x5C)
                return CloseActorChannel = sRef - i;
            else if (*(uint8_t*)(sRef - i) == 0x48 && *(uint8_t*)(sRef - i + 1) == 0x8B && *(uint8_t*)(sRef - i + 2) == 0xC4)
                return CloseActorChannel = sRef - i;
            else if (*(uint8_t*)(sRef - i) == 0x40 && *(uint8_t*)(sRef - i + 1) == 0x55)
                return CloseActorChannel = sRef - i;
        }
    }

    return CloseActorChannel;
}

uint64 FindClientHasInitializedLevelFor()
{
    static uint64_t ClientHasInitializedLevelFor = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        ClientHasInitializedLevelFor = Precision::Patterns({
            "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 8B 5A 20 48 8B F1 4C 8B C3 48 8D",
            "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 8B 5A 20 48 8B F1 4C 8B C3",
            "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 8B F9 48 85 D2 74 35 48",
            "48 89 5C 24 ? 57 48 83 EC 20 48 8B DA 48 8B F9 E8 ? ? ? ? 48 8B D0 48 8B CB E8 ? ? ? ? 48 8B C8",
            "40 53 48 83 EC ? 48 8B D9 48 8B CA E8 ? ? ? ? 48 8B C8 E8 ? ? ? ? 4C 8D 9B",
            "48 89 5C 24 ? 57 48 83 EC 20 8B 81 ? ? ? ? 48 8B F9 48 8B 5A ? 3B 81",
        });
    }

    return ClientHasInitializedLevelFor;
}

uint64 FindStartBecomingDormant()
{
    static uint64_t StartBecomingDormant = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        auto sRef = Precision::FindStringRefSmart(L"StartBecomingDormant: %s");

        if (!sRef)
            return 0;

        for (int i = 0; i < 2000; i++)
        {
            if (*(uint8_t*)(sRef - i) == 0x48 && *(uint8_t*)(sRef - i + 1) == 0x89 && *(uint8_t*)(sRef - i + 2) == 0x5C)
                return StartBecomingDormant = sRef - i;
            else if (*(uint8_t*)(sRef - i) == 0x48 && *(uint8_t*)(sRef - i + 1) == 0x8B && *(uint8_t*)(sRef - i + 2) == 0xC4)
                return StartBecomingDormant = sRef - i;
        }
    }

    return StartBecomingDormant;
}

uint64 FindFlushDormancy()
{
    static uint64_t FlushDormancy = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        auto sRef = Precision::FindStringRefSmart(L"FlushDormancy: %s. Connection: %s");

        if (!sRef)
            return 0;

        for (int i = 0; i < 2000; i++)
        {
            if (*(uint8_t*)(sRef - i) == 0x40 && *(uint8_t*)(sRef - i + 1) == 0x55)
                return FlushDormancy = sRef - i;
            else if (*(uint8_t*)(sRef - i) == 0x4C && *(uint8_t*)(sRef - i + 1) == 0x8B && *(uint8_t*)(sRef - i + 2) == 0xDC)
                return FlushDormancy = sRef - i;
        }
    }

    return FlushDormancy;
}

uint64_t FindEnterAircraft()
{
    static uint64_t EnterAircraft = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        auto sRef = Precision::FindStringRefSmart(L"EnterAircraft: [%s] is attempting to enter aircraft after having already exited.");

        if (!sRef)
            return 0;

        for (int i = 0; i < 1000; i++)
        {
            auto Ptr = (uint8_t*)(sRef - i);

            if (*Ptr == 0x48 && (*(Ptr + 1) == 0x83 || *(Ptr + 1) == 0x81) && *(Ptr + 2) == 0xEC)
            {
                sRef = uint64_t(Ptr);
                break;
            }
            else if (*Ptr == 0x48 && *(Ptr + 1) == 0x8D && *(Ptr + 2) == 0xAC)
            {
                sRef = uint64_t(Ptr);
                break;
            }
        }
        for (int i = 0; i < 1000; i++)
        {
            auto Ptr = (uint8_t*)(sRef - i);

            if (*(uint8_t*)(sRef - i) == 0x40 && (*(uint8_t*)(sRef - i + 1) == 0x53 || *(uint8_t*)(sRef - i + 1) == 0x55))
            {
                EnterAircraft = uint64_t(Ptr);
                break;
            }
            else if (VersionInfo.FortniteVersion >= 15 && *Ptr == 0x48 && *(Ptr + 1) == 0x89 && *(Ptr + 2) == 0x5c)
            {
                EnterAircraft = uint64_t(Ptr);
                break;
            }
            else if (*Ptr == 0x48 && *(Ptr + 1) == 0x89 && *(Ptr + 2) == 0x74)
            {
                EnterAircraft = uint64_t(Ptr);
                break;
            }
        }
    }

    return EnterAircraft;
}

uint64_t FindGetPlayerViewPoint()
{
    uint64 ftspAddr = 0;

    auto ftspRef = Precision::FindStringRefSmart(L"%s failed to spawn a pawn");

    for (int i = 0; i < 1000; i++)
    {
        if (*(uint8_t*)(ftspRef - i) == 0x40 && *(uint8_t*)(ftspRef - i + 1) == 0x53)
        {
            ftspAddr = ftspRef - i;
            break;
        }
        else if (*(uint8_t*)(ftspRef - i) == 0x48 && *(uint8_t*)(ftspRef - i + 1) == 0x89 && *(uint8_t*)(ftspRef - i + 2) == 0x5C)
        {
            ftspAddr = ftspRef - i;
            break;
        }
    }

    if (!ftspAddr)
        return 0;

    auto PCObj = DefaultObjImpl("FortPlayerControllerAthena");
    if (!PCObj)
        return 0;

    auto PCVft = PCObj->Vft;
    int ftspIdx = 0;

    for (int i = 0; i < 0x1000; i++)
    {
        if (PCVft[i] == (void*)ftspAddr)
        {
            ftspIdx = i;
            break;
        }
    }

    if (ftspIdx == 0)
        return 0;

    if (VersionInfo.FortniteVersion >= 20 && *(uint8_t*)(PCVft[ftspIdx - 1]) == 0xE9)
    {
        auto Target = Memcury::Scanner(PCVft[ftspIdx - 1]).RelativeOffset(1).Get();
        if (Target && Precision::InText(Target))
        {
            if (auto Resolved = Precision::ResolveFuncStart(Target))
                return Resolved;
            return Target;
        }
    }

    return __int64(PCVft[ftspIdx - 1]);
}

uint32_t FindOnItemInstanceAddedVft()
{
    static uint32_t OnItemInstanceAddedVft = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        uint64_t OnItemInstanceAdded = 0;

        uint64_t inFunc = 0;
        for (auto Sig : {
                 "41 57 48 83 EC ? 48 8B 01 4C 8B F2 48 8B F1 FF 90 ? ? ? ? 4C 8B F8",
                 "41 56 48 83 EC ? 48 8B 01 4C 8B F2 48 8B F1 FF 90 ? ? ? ? 48 8B F8",
             })
        {
            auto Hits = Precision::FindAllPatterns(Sig);
            if (!Hits.empty())
            {
                inFunc = Hits[0];
                break;
            }
        }

        if (!inFunc)
            return 0;

        for (int i = 0; i < 1000; i++)
        {
            if (*(uint8_t*)(inFunc - i) == 0x48 && *(uint8_t*)(inFunc - i + 1) == 0x8B && *(uint8_t*)(inFunc - i + 2) == 0xC4)
            {
                OnItemInstanceAdded = inFunc - i;
                break;
            }
            else if (*(uint8_t*)(inFunc - i) == 0x48 && *(uint8_t*)(inFunc - i + 1) == 0x89 && *(uint8_t*)(inFunc - i + 2) == 0x74)
            {
                if (*(uint8_t*)(inFunc - i - 5) == 0x48 && *(uint8_t*)(inFunc - i - 4) == 0x89 && *(uint8_t*)(inFunc - i - 3) == 0x5C)
                    i += 5;

                OnItemInstanceAdded = inFunc - i;
                break;
            }
        }

        auto ItemDefObj = DefaultObjImpl("FortItem");
        if (!ItemDefObj)
            return 0;

        for (int i = 0; i < 0x400; i++)
            if (uint64_t(ItemDefObj->Vft[i]) == OnItemInstanceAdded)
                return OnItemInstanceAddedVft = i;
    }

    return OnItemInstanceAddedVft;
}

uint64_t FindGetNamePool()
{
    static uint64_t GetNamePool = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        GetNamePool = Precision::Patterns({
            "48 83 EC ? 80 3D ? ? ? ? ? 0F 84 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C4 ? C3",
            "48 83 EC ? 80 3D ? ? ? ? ? 74 ? 48 8D 05 ? ? ? ? 48 83 C4 ? C3 48 8D 0D",
        });
    }

    return GetNamePool;
}

uint64_t FindIsNetReady()
{
    static uint64_t IsNetReady = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        auto Hits = Precision::FindAllPatterns("84 D2 74 ? 8B 81 ? ? ? ? F7 D8");
        const uint64_t Hit = Hits.empty() ? 0 : Hits[0];

        if (VersionInfo.FortniteVersion >= 20 && Hit)
        {
            if (auto Resolved = Precision::ResolveFuncStart(Hit))
                return IsNetReady = Resolved;
            for (int i = 0; i < 0x30; i++)
            {
                if (*(uint8_t*)(Hit - i) == 0x48 && *(uint8_t*)(Hit - i + 1) == 0x83 && *(uint8_t*)(Hit - i + 2) == 0xEC)
                    return IsNetReady = Hit - i;
            }
            return IsNetReady = Hit;
        }
        else
            IsNetReady = Hit;
    }

    return IsNetReady;
}

uint64_t FindSpawnInitialSafeZone()
{
    static uint64_t SpawnInitialSafeZone = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        auto sRef =
            Precision::FindStringRefSmart(L"FortGameModeAthena::SpawnInitialSafeZone bShouldSpawnSafeZoneIndicator == false, skipping spawning Safe Zone Indicator");

        if (!sRef)
            return 0;

        for (int i = 0; i < 2000; i++)
        {
            auto Ptr = (uint8_t*)(sRef - i);

            if (*Ptr == 0x48 && *(Ptr + 1) == 0x89 && *(Ptr + 2) == 0x5c)
            {
                SpawnInitialSafeZone = uint64_t(Ptr);
                break;
            }
            else if (*Ptr == 0x48 && *(Ptr + 1) == 0x8b && *(Ptr + 2) == 0xc4)
            {
                SpawnInitialSafeZone = uint64_t(Ptr);
                break;
            }
        }
    }

    return SpawnInitialSafeZone;
}

uint64_t FindUpdateSafeZonesPhase()
{
    static uint64_t UpdateSafeZonesPhase = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        auto sRef = Precision::FindStringRefSmart(L"AFortGameModeAthena::UpdateSafeZonesPhase");

        if (!sRef)
            return 0;

        for (int i = 0; i < 2000; i++)
        {
            auto Ptr = (uint8_t*)(sRef - i);

            if (*Ptr == 0x48 && *(Ptr + 1) == 0x89 && *(Ptr + 2) == 0x5c)
            {
                UpdateSafeZonesPhase = uint64_t(Ptr);
                break;
            }
            else if (*Ptr == 0x48 && *(Ptr + 1) == 0x8b && *(Ptr + 2) == 0xc4)
            {
                UpdateSafeZonesPhase = uint64_t(Ptr);
                break;
            }
        }
    }

    return UpdateSafeZonesPhase;
}

uint64 FindUpdateIrisReplicationViews()
{
    static uint64_t UpdateIrisReplicationViews = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        UpdateIrisReplicationViews = Precision::Patterns({
            "48 8B C4 48 89 58 ? 48 89 70 ? 48 89 78 ? 55 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 48 8B "
            "05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 4C 8B F1 E8 ? ? ? ? BB",
            "48 8B C4 48 89 58 ? 48 89 70 ? 48 89 78 ? 55 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 0F 10 0D",
            "48 8B C4 48 89 58 ? 48 89 70 ? 48 89 78 ? 55 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 0F "
            "29 70 ? 0F 29 78 ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 45 33 FF",
        });
    }

    return UpdateIrisReplicationViews;
}

uint64 FindPreSendUpdate()
{
    static uint64_t PreSendUpdate = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        if (auto sRef = Precision::FindStringRefSmart(L"ReplicationSystem_PreSendUpdate"))
            return PreSendUpdate = Memcury::Scanner(sRef).ScanFor({ 0x48, 0x89, 0x5C }, false).Get();

        PreSendUpdate = Precision::Patterns({
            "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 8B 02 48 8B F9 4C 8B 41",
            "48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 55 48 8B EC 48 83 EC ? 8B 02 48 8B F9",
            "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B 71 ? 0F 57 C0",
            "4C 8B DC 49 89 4B ? 55",
        });
    }

    return PreSendUpdate;
}

uint64_t FindHandleMatchHasStarted()
{
    static uint64_t HandleMatchHasStarted = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        auto sRef = Precision::FindStringRefSmart(L"AFortGameModeAthena::HandleMatchHasStarted: NumPlayers: %i");

        if (!sRef)
            sRef = Precision::FindStringRefSmart(L"AFortGameModeAthena::HandleMatchHasStarted: Playlist: %s, NumPlayers: %i");

        if (!sRef)
            return 0;

        for (int i = 0; i < 2000; i++)
        {
            auto Ptr = (uint8_t*)(sRef - i);

            if (*Ptr == 0x48 && *(Ptr + 1) == 0x8b && *(Ptr + 2) == 0xc4)
            {
                HandleMatchHasStarted = uint64_t(Ptr);
                break;
            }
        }
    }

    return HandleMatchHasStarted;
}

uint64_t FindInitializeBuildingActor()
{
    static uint64_t InitializeBuildingActor = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        auto sRef = Precision::FindStringRefSmart(L"STAT_Fort_BuildingSMActorInitializeBuildingActor");

        if (!sRef)
            return 0;

        return InitializeBuildingActor = Memcury::Scanner(sRef).ScanFor(std::vector<uint8_t>{ 0x48, 0x8B, 0xC4 }, false, 0, 1, 1000).Get();
    }

    return InitializeBuildingActor;
}

uint64_t FindPostInitializeSpawnedBuildingActor()
{
    static uint64_t PostInitializeSpawnedBuildingActor = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        auto BuildingObj = DefaultObjImpl("BuildingSMActor");
        if (!BuildingObj)
            return 0;

        auto PCVft = BuildingObj->Vft;
        int ibaIdx = 0;
        auto InitializeBuildingActor = FindInitializeBuildingActor();

        for (int i = 0; i < 2000; i++)
        {
            if (PCVft[i] == (void*)InitializeBuildingActor)
            {
                ibaIdx = i;
                break;
            }
        }

        if (ibaIdx == 0)
            return 0;

        return PostInitializeSpawnedBuildingActor = __int64(PCVft[ibaIdx + 1]);
    }

    return PostInitializeSpawnedBuildingActor;
}

uint64 FindInitializeFlightPath()
{
    static uint64_t InitializeFlightPath = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        InitializeFlightPath = Precision::Pattern("48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 81 EC ? ? ? ? 48 8B E9 41 8A D9");

        if (!InitializeFlightPath)
            InitializeFlightPath = Precision::Pattern("48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 81 EC ? ? ? ? 48 8B E9 41 0F B6 D9");
    }

    return InitializeFlightPath;
}

uint64 FindReset()
{
    static uint64_t Reset = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        Reset = Precision::Pattern("48 89 5C 24 ? 57 48 83 EC ? 48 8B 91 ? ? ? ? 48 8B F9 48 85 D2 74 ? 48 8B 01");
    }

    return Reset;
}

uint64_t FindNotifyGameMemberAdded()
{
    static uint64_t NotifyGameMemberAdded = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        if (VersionInfo.EngineVersion >= 5.1)
        {
            NotifyGameMemberAdded = Precision::Pattern("40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 88 54 24");

            if (!NotifyGameMemberAdded)
                NotifyGameMemberAdded = Precision::Pattern("40 55 53 56 57 41 54 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 88 54 24");

            if (!NotifyGameMemberAdded)
                NotifyGameMemberAdded = Precision::Pattern("40 55 53 56 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 88 54 24");

            return NotifyGameMemberAdded;
        }

        auto sRef = Precision::FindStringRefSmart(L"%s: Adding Player state with UniqueId: %s, in team: %d, and in squad: %d");

        if (!sRef)
            return 0;

        for (int i = 0; i < 2000; i++)
        {
            auto Ptr = (uint8_t*)(sRef - i);

            if (*Ptr == 0x40 && *(Ptr + 1) == 0x55)
            {
                NotifyGameMemberAdded = uint64_t(Ptr);
                break;
            }
        }
    }

    return NotifyGameMemberAdded;
}

uint64 FindSetGamePhase()
{
    static uint64_t SetGamePhase = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        SetGamePhase = Precision::Pattern("48 8B C4 48 89 58 ? 48 89 70 ? 48 89 78 ? 55 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 "
                                                     "33 C4 48 89 85 ? ? ? ? 48 8B 81 ? ? ? ? 4C 8B E9 44 0F B6 E2");
    }

    return SetGamePhase;
}

uint64_t FindPayBuildableClassPlacementCost()
{
    auto sRef = Precision::FindStringRefSmart(L"Failed to remove item %s during pay building costs, item duplicated!");

    if (VersionInfo.FortniteVersion >= 10.00)
    {
        if (auto Addr = Precision::Pattern("48 89 5C 24 ? 48 89 74 24 ? 55 57 41 54 41 56 41 57 48 8B EC 48 81 EC ? ? ? ? 48 8B 1A 33 FF"))
            return Addr;
    }

    if (sRef)
    {
        for (int i = 0; i < 2000; i++)
        {
            auto Ptr = (uint8_t*)(sRef - i);

            if (*Ptr == 0x48 && *(Ptr + 1) == 0x8B && *(Ptr + 2) == 0xC4)
                return uint64_t(Ptr);
            else if (*Ptr == 0x48 && *(Ptr + 1) == 0x89 && *(Ptr + 2) == 0x5C)
                return uint64_t(Ptr);
        }
    }

    return Precision::Pattern("48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 56 48 83 EC ? 48 8B 1A 33 F6");
}

uint64_t FindCanAffordToPlaceBuildableClass()
{
    auto sRef = Precision::FindStringRefSmart(L"Resource not found! Resource Type is %i, might be invalid");

    if (VersionInfo.FortniteVersion >= 18)
    {
        if (auto Addr = Precision::Patterns({
                "48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 56 48 83 EC ? 33 DB 4C 8B F2 48 8B F9 48 39 1A",
                "48 8B C4 48 89 58 ? 48 89 68 ? 48 89 70 ? 48 89 78 ? 41 56 48 83 EC ? 33 DB 4C 8B F2 48 8B F9 48 39 1A",
            }))
            return Addr;
    }

    if (sRef)
    {
        if (VersionInfo.FortniteVersion < 12.00)
        {
            for (int i = 0; i < 2000; i++)
            {
                auto Ptr = (uint8_t*)(sRef - i);

                if (*Ptr == 0x40 && (*(Ptr + 1) == 0x57 || *(Ptr + 1) == 0x55 || *(Ptr + 1) == 0x53 || *(Ptr + 1) == 0x56))
                    return uint64_t(Ptr);
            }
        }
        else
            for (int i = 0; i < 2000; i++)
            {
                auto Ptr = (uint8_t*)(sRef - i);

                if (*Ptr == 0x48 && *(Ptr + 1) == 0x8B && *(Ptr + 2) == 0xC4)
                    return uint64_t(Ptr);
                else if (*Ptr == 0x48 && *(Ptr + 1) == 0x89 && *(Ptr + 2) == 0x5C)
                    return uint64_t(Ptr);
            }
    }
    else
        return Precision::Pattern("40 53 56 41 56 48 83 EC ? 48 8B 1A 4C 8B F2");
    return 0;
}

uint64 FindCanPlaceBuildableClassInStructuralGrid()
{
    static uint64_t CanPlaceBuildableClassInStructuralGrid = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        CanPlaceBuildableClassInStructuralGrid = Precision::Pattern("48 8B C4 48 89 58 ? 48 89 68 ? 48 89 70 ? 48 89 78 ? 41 54 41 56 41 57 48 83 EC ? 4D 8B E1 4D 8B F8 48 8B F2");

        if (!CanPlaceBuildableClassInStructuralGrid)
            CanPlaceBuildableClassInStructuralGrid = Precision::Pattern("48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 54 41 55 41 56 41 57 48 83 EC ? 48 8B 1A 4D 8B E9");
    }

    return CanPlaceBuildableClassInStructuralGrid;
}

uint64 FindLoadPlayset(const std::vector<uint8_t>& Bytes, int recursive)
{
    static uint64_t LoadPlayset = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        if (VersionInfo.EngineVersion >= 5.0)
        {
            LoadPlayset = Precision::Pattern("48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 4C 8B B1 ? ? ? ? 45");

            if (!LoadPlayset)
                LoadPlayset = Precision::Pattern("48 8B C4 48 89 58 ? 48 89 70 ? 48 89 78 ? 55 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 48 8B B1 ? ? ? ? 45");

            if (!LoadPlayset)
                LoadPlayset = Precision::Pattern("48 8B C4 48 89 58 ? 48 89 70 ? 48 89 78 ? 55 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 4C 8B A9");

            if (!LoadPlayset)
                LoadPlayset = Precision::Pattern("48 8B C4 48 89 58 ? 48 89 70 ? 48 89 78 ? 55 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 4C 8B B9");

            if (!LoadPlayset)
                LoadPlayset = Precision::Pattern("48 8B C4 48 89 58 ? 48 89 70 ? 48 89 78 ? 55 41 54 41 55 41 56 41 57 48 8D 68 ? 48 81 EC ? ? ? ? 4C 8B A9");

            if (!LoadPlayset)
                LoadPlayset = Precision::Pattern("48 8B C4 48 89 58 ? 48 89 70 ? 55 57 41 54 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 4C 8B A1");

            return LoadPlayset;
        }

        if (recursive >= 2)
            return 0;

        auto StringRef = Precision::FindStringRefSmart(L"UPlaysetLevelStreamComponent::LoadPlayset Error: no owner for %s", 1);

        if (!StringRef)
            return 0;

        for (int i = 0; i < 400; i++)
        {
            auto CurrentByte = *(uint8_t*)(StringRef - i);

            if (CurrentByte == Bytes[0])
            {
                bool Found = true;
                for (int j = 1; j < Bytes.size(); j++)
                    if (*(uint8_t*)(StringRef - i + j) != Bytes[j])
                    {
                        Found = false;
                        break;
                    }

                if (Found)
                    return LoadPlayset = StringRef - i;
            }

            if (CurrentByte == 0xC3)
                return FindLoadPlayset({ 0x40, 0x55 }, ++recursive);
        }

        return 0;
    }

    return LoadPlayset;
}

uint32 FindSpawnDecoVft()
{
    auto sRef = Precision::FindStringRefSmart(L"AFortTrapTool::SpawnDeco World is tearing down.  Early-ing out.");

    if (!sRef)
        return 0;

    uint64 SpawnDeco = 0;
    for (int i = 0; i < 2000; i++)
    {
        if (!Precision::InTextRange(sRef - i, 3))
            break;
        auto Ptr = (uint8_t*)(sRef - i);

        if (*Ptr == 0x48 && *(Ptr + 1) == 0x8B && *(Ptr + 2) == 0xC4)
        {
            SpawnDeco = uint64_t(Ptr);
            break;
        }
        else if (*Ptr == 0x48 && *(Ptr + 1) == 0x89 && *(Ptr + 2) == 0x5C)
        {
            SpawnDeco = uint64_t(Ptr);
            break;
        }
    }

    auto TrapObj = DefaultObjImpl("FortTrapTool");
    if (!TrapObj)
        return 0;

    auto ActorVft = TrapObj->Vft;

    for (int i = 0; i < 0x500; i++)
    {
        if (ActorVft[i] == (void*)SpawnDeco)
        {
            return i;
        }
    }
    return 0;
}

uint32 FindShouldAllowServerSpawnDecoVft()
{
    auto sRef = Precision::FindStringRefSmart(L"Tried to place deco item %s %s that isn't actually in player inventory!");

    if (!sRef)
        return 0;

    uint64 ShouldAllowServerSpawnDecoPart = 0;

    for (int i = 0; i < 2000; i++)
    {
        if (!Precision::InTextRange(sRef - i, 3))
            break;
        auto Ptr = (uint8_t*)(sRef - i);

        if (*Ptr == 0x48 && *(Ptr + 1) == 0x83 && *(Ptr + 2) == 0xEC)
        {
            ShouldAllowServerSpawnDecoPart = uint64_t(Ptr);
            break;
        }
        else if (*Ptr == 0x48 && *(Ptr + 1) == 0x81 && *(Ptr + 2) == 0xEC)
        {
            ShouldAllowServerSpawnDecoPart = uint64_t(Ptr);
            break;
        }
    }

    if (!ShouldAllowServerSpawnDecoPart)
        return 0;

    uint64 ShouldAllowServerSpawnDeco = 0;
    for (int i = 0; i < 2000; i++)
    {
        if (!Precision::InTextRange(ShouldAllowServerSpawnDecoPart - i, 3))
            break;
        auto Ptr = (uint8_t*)(ShouldAllowServerSpawnDecoPart - i);

        if (*Ptr == 0x48 && *(Ptr + 1) == 0x8B && *(Ptr + 2) == 0xC4)
        {
            ShouldAllowServerSpawnDeco = uint64_t(Ptr);
            break;
        }
        else if (*Ptr == 0x48 && *(Ptr + 1) == 0x89 && *(Ptr + 2) == 0x5C)
        {
            ShouldAllowServerSpawnDeco = uint64_t(Ptr);
            break;
        }
    }

    auto DecoObj = DefaultObjImpl("FortDecoTool");
    if (!DecoObj)
        return 0;

    auto ActorVft = DecoObj->Vft;

    for (int i = 0; i < 0x500; i++)
    {
        if (ActorVft[i] == (void*)ShouldAllowServerSpawnDeco)
        {
            return i;
        }
    }
    return 0;
}

uint64 FindSetState()
{
    auto sRef = Precision::FindStringRefSmart(L"Time from Setup to InProgress: %6.2fms");

    if (!sRef)
        return 0;

    for (int i = 0; i < 2000; i++)
    {
        auto Ptr = (uint8_t*)(sRef - i);

        if (*Ptr == 0x48 && *(Ptr + 1) == 0x8B && *(Ptr + 2) == 0xC4)
            return uint64_t(Ptr);
        else if (*Ptr == 0x48 && *(Ptr + 1) == 0x89 && *(Ptr + 2) == 0x5C)
            return uint64_t(Ptr);
    }

    return 0;
}

uint64 FindMinigameSettingsBuilding__BeginPlay()
{
    return Precision::Pattern("40 55 57 41 56 41 57 48 8B EC 48 83 EC ? 80 3D");
}

uint64_t FindPickSupplyDropLocation()
{
    auto sRef = Precision::FindStringRefSmart(L"PickSupplyDropLocation: Failed to find valid location using rejection.  Using safe zone location.");

    if (!sRef)
        sRef = Precision::FindStringRefSmart(L"AFortAthenaMapInfo::PickSupplyDropLocation");

    if (!sRef)
        return 0;

    for (int i = 0; i < 2000; i++)
    {
        if (!Precision::InTextRange(sRef - i, 3))
            break;
        auto Ptr = (uint8_t*)(sRef - i);

        if (*Ptr == 0x48 && *(Ptr + 1) == 0x8B && *(Ptr + 2) == 0xC4)
            return uint64_t(Ptr);
        else if (*Ptr == 0x48 && *(Ptr + 1) == 0x89 && *(Ptr + 2) == 0x5C)
            return uint64_t(Ptr);
    }

    return 0;
}

uint64_t FindSetPickupTarget()
{
    auto sRef = Precision::FindStringRefSmart(L"%s: Attempted to spawn non-world item %s!");

    if (!sRef)
        sRef = Precision::FindStringRefSmart(L"Attempted to spawn non-world item %s!");

    if (!sRef)
        return 0;

    for (int i = 0; i < 0x1500; i++)
    {
        if (!Precision::InTextRange(sRef - i, 3))
            break;
        auto Ptr = (uint8_t*)(sRef - i);

        if (*Ptr == 0x40 && (*(Ptr + 1) == 0x53 || *(Ptr + 1) == 0x55))
            return uint64_t(Ptr);
        else if (*Ptr == 0x48 && *(Ptr + 1) == 0x8B && *(Ptr + 2) == 0xC4)
            return uint64_t(Ptr);
        else if (*Ptr == 0x4C && *(Ptr + 1) == 0x8B && *(Ptr + 2) == 0xDC)
            return uint64_t(Ptr);
    }

    return 0;
}

uint64 FindInitializePlayerGameplayAbilities()
{
    auto sRef = Precision::FindStringRefSmart(L"InitializePlayerGameplayAbilities with invalid PlayerStateOrProxy!");

    if (!sRef)
        return 0;

    for (int i = 0; i < 2000; i++)
    {
        auto Ptr = (uint8_t*)(sRef - i);

        if (*Ptr == 0x48 && *(Ptr + 1) == 0x8B && *(Ptr + 2) == 0xC4)
            return uint64_t(Ptr);
        else if (*Ptr == 0x48 && *(Ptr + 1) == 0x89 && *(Ptr + 2) == 0x5C)
            return uint64_t(Ptr);
        else if (*Ptr == 0x48 && *(Ptr + 1) == 0x89 && *(Ptr + 2) == 0x4C)
            return uint64_t(Ptr);
        else if (*Ptr == 0x40 && *(Ptr + 1) == 0x57)
            return uint64_t(Ptr);
    }

    return 0;
}

uint64 FindListenCall()
{
    static uint64_t ListenCall = 0;
    static bool bInitialized = false;

    if (!bInitialized)
    {
        bInitialized = true;

        if (VersionInfo.FortniteVersion <= 6 || VersionInfo.FortniteVersion > 16)
            return ListenCall = 0;

        auto sRef = Precision::FindStringRefSmart(L"LoadMap: failed to Listen(%s)");

        if (!sRef)
            return ListenCall = 0;

        for (int i = 0; i < 0x100; i++)
        {
            auto Ptr = (uint8_t*)(sRef - i);

            if (*Ptr == 0xE8 && *(Ptr + 5) == 0x84 && *(Ptr + 6) == 0xC0)
                return ListenCall = uint64_t(Ptr);
        }

        return 0;
    }

    return ListenCall;
}

uint64 FindQueueStatEvent()
{
    auto sRef =
        Precision::FindStringRefSmart(L"UFortQuestManager::QueueStatEvent: %s tried to queue a stat event, but the player controller is null. \n\t Event: %s");

    if (!sRef)
        return 0;

    for (int i = 0; i < 2000; i++)
    {
        auto Ptr = (uint8_t*)(sRef - i);

        if (*Ptr == 0x48 && *(Ptr + 1) == 0x8B && *(Ptr + 2) == 0xC4)
            return uint64_t(Ptr);
        else if (*Ptr == 0x48 && *(Ptr + 1) == 0x89 && *(Ptr + 2) == 0x5C)
            return uint64_t(Ptr);
        else if (*Ptr == 0x40 && *(Ptr + 1) == 0x55)
            return uint64_t(Ptr);
    }

    return 0;
}

uint64 FindFinishWorldInitialization()
{
    uint64_t Anchor = Precision::FindStringRefSmart(L"Can't find a FortAthenaMapInfo placed in map.  Skipping warmup and aircraft phases.");

    if (!Anchor)
    {
        auto MeshSRef = Precision::FindStringRefSmart(L"bEnableMeshNetwork");

        if (!MeshSRef)
        {
            return Precision::Pattern("48 89 5C 24 ? 48 89 74 24 ? 55 57 41 56 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 ? 48 8B F9 E8 ? ? ? ? 48 8B CF 4C 8B F0");
        }

        uint64_t ShouldPIESetDefaultPlaylistPart = 0;
        for (int i = 0; i < 2000; i++)
        {
            if (!Precision::InTextRange(MeshSRef - i, 3))
                break;
            auto Ptr = (uint8_t*)(MeshSRef - i);

            if (*Ptr == 0x48 && *(Ptr + 1) == 0x83 && *(Ptr + 2) == 0xEC)
            {
                ShouldPIESetDefaultPlaylistPart = uint64_t(Ptr);
                break;
            }
            else if (*Ptr == 0x48 && *(Ptr + 1) == 0x81 && *(Ptr + 2) == 0xEC)
            {
                ShouldPIESetDefaultPlaylistPart = uint64_t(Ptr);
                break;
            }
        }

        uint64_t ShouldPIESetDefaultPlaylist = 0;

        if (ShouldPIESetDefaultPlaylistPart)
        for (int i = 0; i < 2000; i++)
        {
            if (!Precision::InTextRange(ShouldPIESetDefaultPlaylistPart - i, 3))
                break;
            auto Ptr = (uint8_t*)(ShouldPIESetDefaultPlaylistPart - i);

            if (*Ptr == 0x48 && *(Ptr + 1) == 0x8B && *(Ptr + 2) == 0xC4)
            {
                ShouldPIESetDefaultPlaylist = uint64_t(Ptr);
                break;
            }
            else if (*Ptr == 0x48 && *(Ptr + 1) == 0x89 && *(Ptr + 2) == 0x5C)
            {
                ShouldPIESetDefaultPlaylist = uint64_t(Ptr);
                break;
            }
            else if (*Ptr == 0x4C && *(Ptr + 1) == 0x8B && *(Ptr + 2) == 0xDC)
            {
                ShouldPIESetDefaultPlaylist = uint64_t(Ptr);
                break;
            }
            else if (*Ptr == 0x40 && *(Ptr + 1) == 0x55)
            {
                ShouldPIESetDefaultPlaylist = uint64_t(Ptr);
                break;
            }
        }

        Anchor = Memcury::Scanner::FindPointerRef((void*)ShouldPIESetDefaultPlaylist).Get();
    }

    if (!Anchor)
        return 0;

    uint64_t FinishWorldInitializationPart = 0;
    for (int i = 0; i < 2000; i++)
    {
        if (!Precision::InTextRange(Anchor - i, 3))
            break;
        auto Ptr = (uint8_t*)(Anchor - i);

        if (*Ptr == 0x48 && *(Ptr + 1) == 0x83 && *(Ptr + 2) == 0xEC)
        {
            FinishWorldInitializationPart = uint64_t(Ptr);
            break;
        }
        else if (*Ptr == 0x48 && *(Ptr + 1) == 0x81 && *(Ptr + 2) == 0xEC)
        {
            FinishWorldInitializationPart = uint64_t(Ptr);
            break;
        }
    }

    if (!FinishWorldInitializationPart)
        return 0;

    for (int i = 0; i < 2000; i++)
    {
        if (!Precision::InTextRange(FinishWorldInitializationPart - i, 3))
            break;
        auto Ptr = (uint8_t*)(FinishWorldInitializationPart - i);

        if (*Ptr == 0x48 && *(Ptr + 1) == 0x8B && *(Ptr + 2) == 0xC4)
            return uint64_t(Ptr);
        else if (*Ptr == 0x48 && *(Ptr + 1) == 0x89 && *(Ptr + 2) == 0x5C)
            return uint64_t(Ptr);
        else if (*Ptr == 0x4C && *(Ptr + 1) == 0x8B && *(Ptr + 2) == 0xDC)
            return uint64_t(Ptr);
        else if (*Ptr == 0x40 && *(Ptr + 1) == 0x55)
            return uint64_t(Ptr);
    }

    return 0;
}

uint64 FindActivatePhase()
{
    auto sRef = Precision::FindStringRefSmart(L"[ASpecialEventScript::ActivatePhase()] [%s] New Phase [%s] OldPhase [%s] SequenceTimeOffset [%f]");

    if (!sRef)
        sRef = Precision::FindStringRefSmart(L"[ASpecialEventScript::ActivatePhase()] [%s] New Phase [%s] OldPhase [%s]");

    if (!sRef)
        return 0;

    uint64 ActivatePhasePart = 0;

    for (int i = 0; i < 2000; i++)
    {
        if (!Precision::InTextRange(sRef - i, 3))
            break;
        auto Ptr = (uint8_t*)(sRef - i);

        if (*Ptr == 0x48 && *(Ptr + 1) == 0x83 && *(Ptr + 2) == 0xEC)
        {
            ActivatePhasePart = uint64_t(Ptr);
            break;
        }
        else if (*Ptr == 0x48 && *(Ptr + 1) == 0x81 && *(Ptr + 2) == 0xEC)
        {
            ActivatePhasePart = uint64_t(Ptr);
            break;
        }
    }

    if (!ActivatePhasePart)
        return 0;

    for (int i = 0; i < 2000; i++)
    {
        if (!Precision::InTextRange(ActivatePhasePart - i, 3))
            break;
        auto Ptr = (uint8_t*)(ActivatePhasePart - i);

        if (*Ptr == 0x48 && *(Ptr + 1) == 0x8B && *(Ptr + 2) == 0xC4)
            return uint64_t(Ptr);
        else if (*Ptr == 0x48 && *(Ptr + 1) == 0x89 && *(Ptr + 2) == 0x5C)
            return uint64_t(Ptr);
        else if (*Ptr == 0x40 && *(Ptr + 1) == 0x55)
            return uint64_t(Ptr);
    }

    return 0;
}

auto FindCmpRef(void* Pointer) -> Memcury::Scanner
{
    Memcury::PE::Address add{ nullptr };

    if (!Pointer)
        return Memcury::Scanner(add);

    auto textSection = Memcury::PE::Section::GetSection(".text");

    const auto scanBytes = reinterpret_cast<std::uint8_t*>(textSection.GetSectionStart().Get());

    int aa = 0;

    __m128i t = _mm_set1_epi8((char)0x39);
    __m128i t2 = _mm_set1_epi8((char)0x83);
    DWORD i = 0;

    for (; i < textSection.GetSectionSize() - (textSection.GetSectionSize() % 16); i += 16)
    {
        auto bytes = _mm_load_si128((const __m128i*)(scanBytes + i));
        int offset = _mm_movemask_epi8(_mm_cmpeq_epi8(bytes, t));

        if (offset != 0)
        {
            for (int q = 0; q < 16; q++)
            {
                int c = offset & (1 << q);
                if (c)
                {
                    if (Memcury::PE::Address(&scanBytes[i + q]).RelativeOffset(2).GetAs<void*>() == Pointer)
                    {
                        add = Memcury::PE::Address(&scanBytes[i + q]);

                        goto _ret;
                    }
                }
            }
        }

        int offset2 = _mm_movemask_epi8(_mm_cmpeq_epi8(bytes, t2));

        if (offset2 != 0)
        {
            for (int q = 0; q < 16; q++)
            {
                int c = offset2 & (1 << q);
                if (c)
                {
                    if (Memcury::PE::Address(&scanBytes[i + q]).RelativeOffset(2, 1).GetAs<void*>() == Pointer)
                    {
                        add = Memcury::PE::Address(&scanBytes[i + q]);

                        goto _ret;
                    }
                }
            }
        }
    }
_ret:

    return Memcury::Scanner(add);
}

uint64 FindSetIsDoorOpen()
{
    auto CVar = FindCVar<void>(L"Athena.EnableSlammingThroughDoorsKnockbackPawns");
    if (!CVar)
        return 0;

    auto CVarRef = FindCmpRef(CVar);

    if (!CVarRef.IsValid())
        return 0;

    printf("CVarRef: %llx\n", CVarRef.Get() - ImageBase);
    uint64_t SetIsDoorOpenPart = 0;
    for (int i = 0; i < 0x10000; i++)
    {
        auto Ptr = (uint8_t*)(CVarRef.Get() - i);

        if (*Ptr == 0x48 && *(Ptr + 1) == 0x83 && *(Ptr + 2) == 0xEC)
        {
            SetIsDoorOpenPart = uint64_t(Ptr);
            break;
        }
        else if (*Ptr == 0x48 && *(Ptr + 1) == 0x81 && *(Ptr + 2) == 0xEC)
        {
            SetIsDoorOpenPart = uint64_t(Ptr);
            break;
        }
    }
    printf("CVarRef: %llx\n", SetIsDoorOpenPart - ImageBase);

    if (SetIsDoorOpenPart)
        for (int i = 0; i < 2000; i++)
        {
            auto Ptr = (uint8_t*)(SetIsDoorOpenPart - i);

            if (*Ptr == 0x48 && *(Ptr + 1) == 0x8B && *(Ptr + 2) == 0xC4)
                return uint64_t(Ptr);
            else if (*Ptr == 0x48 && *(Ptr + 1) == 0x89 && *(Ptr + 2) == 0x5C)
                return uint64_t(Ptr);
            else if (*Ptr == 0x40 && *(Ptr + 1) == 0x55)
                return uint64_t(Ptr);
        }

    return 0;
}

uint64 FindSelectAndSetupMyBuildingLevel()
{
    auto sRef = Precision::FindStringRefSmart(L"ABuildingFoundation::SelectAndSetupMyBuildingLevel - Cannot get WorldManager!!");

    if (!sRef)
        return 0;

    uint64_t SelectAndSetupMyBuildingLevelPart = 0;
    for (int i = 0; i < 2000; i++)
    {
        if (!Precision::InTextRange(sRef - i, 3))
            break;
        auto Ptr = (uint8_t*)(sRef - i);

        if (*Ptr == 0x48 && *(Ptr + 1) == 0x83 && *(Ptr + 2) == 0xEC)
        {
            SelectAndSetupMyBuildingLevelPart = uint64_t(Ptr);
            break;
        }
        else if (*Ptr == 0x48 && *(Ptr + 1) == 0x81 && *(Ptr + 2) == 0xEC)
        {
            SelectAndSetupMyBuildingLevelPart = uint64_t(Ptr);
            break;
        }
    }

    if (!SelectAndSetupMyBuildingLevelPart)
        return 0;

    for (int i = 0; i < 2000; i++)
    {
        if (!Precision::InTextRange(SelectAndSetupMyBuildingLevelPart - i, 3))
            break;
        auto Ptr = (uint8_t*)(SelectAndSetupMyBuildingLevelPart - i);

        if (*Ptr == 0x48 && *(Ptr + 1) == 0x8B && *(Ptr + 2) == 0xC4)
            return uint64_t(Ptr);
        else if (*Ptr == 0x48 && *(Ptr + 1) == 0x89 && *(Ptr + 2) == 0x5C)
            return uint64_t(Ptr);
        else if (*Ptr == 0x40 && *(Ptr + 1) == 0x55)
            return uint64_t(Ptr);
    }

    return 0;
}

void FindNullsAndRetTrues()
{
    if (VersionInfo.EngineVersion == 4.16)
    {
        // NullFuncs.push_back(Memcury::Scanner::FindPattern("4C 89 44 24 ? 88 54 24 ? 48 89 4C 24 ? 56 57 48 81 EC ? ? ? ? 33 C0 83 F8 ? 0F 84 ? ? ? ? B8").Get());
        NullFuncs.push_back(Precision::Pattern("48 89 54 24 ? 48 89 4C 24 ? 55 53 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 8B 41 08 C1 E8 05"));
        // NullFuncs.push_back(Memcury::Scanner::FindPattern("48 89 54 24 ? 48 89 4C 24 ? 55 53 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 8B 41 ? C1 E8 ? A8 ? 0F 84 ? ? ? ? 80 3D").Get());
    }
    else if (VersionInfo.EngineVersion == 4.20)
    {
        NullFuncs.push_back(Memcury::Scanner(Precision::FindStringRefSmart(L"Widget Class %s - Running Initialize On Archetype, %s.")).ScanFor(std::vector<uint8_t>{ 0x48, 0x89, 0x54 }, false).Get());
        if (VersionInfo.FortniteVersion > 3.2)
        {
            // if (VersionInfo.FortniteVersion == 4.1)
            //     NullFuncs.push_back(Memcury::Scanner::FindPattern("4C 8B DC 55 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 49 89 5B 10 48 8D 05
            //     ? ? ? ? 48 8B 1D ? ? ? ? 49 89 73 18 33 F6 40").Get());

            NullFuncs.push_back(Precision::Pattern("48 8B C4 57 48 81 EC ? ? ? ? 4C 8B 82 ? ? ? ? 48 8B F9 0F 29 70 E8 0F 29 78 D8"));
            // NullFuncs.push_back(Memcury::Scanner::FindPattern("4C 8B DC 55 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 49 89 5B 10 48 8D 05 ? ?
            // ? ? 48 8B 1D ? ? ? ? 49 89 73 18 33 F6 40").Get());
        }
        // else
        //     NullFuncs.push_back(Memcury::Scanner::FindPattern("E8 ? ? ? ? F0 FF 0D ? ? ? ? 0F B6 C3").RelativeOffset(1).Get());
    }
    else if (VersionInfo.EngineVersion == 4.21)
    {
        NullFuncs.push_back(Precision::Pattern("48 8B C4 48 89 58 08 48 89 70 10 57 48 81 EC ? ? ? ? 48 8B BA ? ? ? ? 48 8B DA 0F 29"));
        NullFuncs.push_back(Memcury::Scanner(Precision::FindStringRefSmart(L"Widget Class %s - Running Initialize On Archetype, %s."))
                                .ScanFor(VersionInfo.FortniteVersion < 6.3 ? std::vector<uint8_t>{ 0x40, 0x55 } : std::vector<uint8_t>{ 0x48, 0x89, 0x5C }, false)
                                .Get());
        NullFuncs.push_back(Precision::Pattern("48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 41 56 48 83 EC 30 41 0F B6 F0 48 8D 15 ? ? ? ? 48 8B F9 41 B8"));
    }
    else if (VersionInfo.EngineVersion >= 4.22 && VersionInfo.FortniteVersion <= 12.00)
    {
        if (VersionInfo.EngineVersion == 4.24)
            NullFuncs.push_back(Precision::Pattern("40 53 57 48 83 EC ? 48 8B 01 48 8B F9 FF 90 ? ? ? ? 48 8B C8"));
        // else if (VersionInfo.EngineVersion == 4.25)
        //     NullFuncs.push_back(Memcury::Scanner::FindPattern("40 57 41 56 48 81 EC ? ? ? ? 80 3D ? ? ? ? ? 0F B6 FA 44 8B F1 74 3A 80 3D ? ? ? ? ? 0F 82").Get());
        NullFuncs.push_back(Precision::Pattern("48 89 5C 24 ? 57 48 83 EC 30 48 8B 41 28 48 8B DA 48 8B F9 48 85 C0 74 34 48 8B 4B 08 48 8D"));
    }
    else if (VersionInfo.EngineVersion == 4.25)
    {
        // NullFuncs.push_back(Memcury::Scanner::FindStringRef(L"Widget Class %s - Running Initialize On Archetype, %s.").ScanFor(std::vector<uint8_t>{ 0x48, 0x89, 0x5C },
        // false).Get()); // for 12.41 NullFuncs.push_back(Memcury::Scanner::FindPattern(VersionInfo.FortniteVersion == 12.41 ? "40 57 41 56 48 81 EC ? ? ? ? 80 3D ? ? ? ? ? 0F B6
        // FA 44 8B F1 74 3A 80 3D ? ? ? ? ? 0F" : "40 57 41 56 48 81 EC ? ? ? ? 80 3D ? ? ? ? ? 0F B6 FA 44 8B F1 74 3A 80 3D ? ? ? ? ? 0F 82").Get()); if
        // if (VersionInfo.FortniteVersion == 12.41)
        //     NullFuncs.push_back(Memcury::Scanner::FindPattern("48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC ? 48 8B FA 4C 8B F9").Get());
        /*else */ if (VersionInfo.FortniteVersion == 12.61)
            NullFuncs.push_back(Precision::Pattern("48 89 5C 24 ? 55 57 41 54 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 20 4C 8B A5"));
    }
    else if (VersionInfo.FortniteVersion == 14.60)
        NullFuncs.push_back(Precision::Pattern("40 55 57 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 80 3D ? ? ? ? ? 0F B6 FA 44 8B F9 74 3B 80 3D ? ? ? ? ? 0F"));
    else if (VersionInfo.FortniteVersion >= 17.00)
    {
        // NullFuncs.push_back(Memcury::Scanner::FindPattern("48 89 5C 24 10 48 89 6C 24 20 56 57 41 54 41 56 41 57 48 81 EC ? ? ? ? 65 48 8B 04 25 ? ? ? ? 4C 8B F9").Get());
        if (std::floor(VersionInfo.FortniteVersion) == 17)
            NullFuncs.push_back(Precision::Pattern("48 8B C4 48 89 70 08 48 89 78 10 55 41 54 41 55 41 56 41 57 48 8D 68 A1 48 81 EC ? ? ? ? 45 33 ED"));
        else if (VersionInfo.FortniteVersion >= 19.00 && VersionInfo.FortniteVersion < 20.00)
        {
            auto p = Precision::Pattern("48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 55 41 55 41 56 48 8B EC 48 83 EC 50 83 65 28 00 40 B6 05 40 38 35 ? ? ? ? 4C");

            if (!p)
                p = Precision::Pattern("48 89 5C 24 ? 48 89 74 24 ? 55 57 41 56 48 8B EC 48 83 EC ? 83 65 ? ? 40 B6");

            NullFuncs.push_back(p);
        }
        else if (VersionInfo.FortniteVersion >= 20.00 && VersionInfo.EngineVersion == 5.0)
        {
            NullFuncs.push_back(Precision::Pattern("48 8B C4 48 89 58 08 4C 89 40 18 48 89 50 10 55 56 57 41 54 41 55 41 56 41 57 48 8D 68 98 48 81 EC ? ? ? ? 49 8B 48 20 45 33"));
            NullFuncs.push_back(Precision::Pattern("48 89 5C 24 ? 57 48 83 EC 20 48 8B 41 20 48 8B FA 48 8B D9 BA ? ? ? ? 83 78 08 03 0F 8D"));
            NullFuncs.push_back(Precision::Pattern("4C 89 44 24 ? 53 55 56 57 41 54 41 55 41 56 41 57 48 83 EC 68 48 8D 05 ? ? ? ? 0F"));
            NullFuncs.push_back(Precision::Pattern("48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 30 48 8B F9 48 8B CA E8"));
            NullFuncs.push_back(Precision::Pattern("48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 ? 41 ? 48 83 EC 60 45 33 F6 4C 8D ? ? ? ? ? 48 8B DA"));
        }
        // else if (VersionInfo.EngineVersion == 5.1)
        //     NullFuncs.push_back(Memcury::Scanner::FindPattern("48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? B8 ? ? ? ? E8 ? ? ? ? 48 2B E0 48 8B 05 ? ? ? ?
        //     48 33 C4 48 89 85 ? ? ? ? 4D 8B F1").Get());
        else if (VersionInfo.EngineVersion == 5.2)
            NullFuncs.push_back(
                Precision::Pattern("48 8B C4 48 89 58 ? 55 56 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? 0F 29 70 ? 48 8D 6C 24 ? 48 83 E5 ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 4C 8B F2"));
        else if (VersionInfo.EngineVersion == 5.3)
            NullFuncs.push_back(Precision::Pattern("48 8B C4 48 89 58 ? 48 89 70 ? 55 57 41 54 41 56 41 57 48 81 EC"));
        else if (VersionInfo.EngineVersion >= 5.4)
            NullFuncs.push_back(
                Precision::Pattern("48 8B C4 48 89 58 ? 48 89 70 ? 55 57 41 54 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 0F 29 70 ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 45 33 FF"));
    }

    if (VersionInfo.FortniteVersion == 2.5)
        NullFuncs.push_back(Precision::Pattern("40 55 56 41 56 48 8B EC 48 81 EC ? ? ? ? 48 8B 01 4C 8B F2"));
    else if (VersionInfo.EngineVersion == 5.0)
    {
        auto pattern = Precision::Pattern("48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC 50 4C 8B FA 48 8B F1 E8");

        if (!pattern)
            pattern = Precision::Pattern("48 89 5C 24 ? 48 89 74 24 ? 55 57 41 54 41 55 41 56 48 8B EC 48 83 EC ? 4C 8B F2");

        NullFuncs.push_back(pattern);
    }
    else if (VersionInfo.EngineVersion == 5.1 || VersionInfo.EngineVersion == 5.2)
    {
        auto pattern = Precision::Pattern("48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 55 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC ? 4C 8B E2 4C 8B F1 E8 ? ? ? ? 48 8B 0D");

        if (!pattern)
            pattern = Precision::Pattern("48 89 5C ? ? 55 56 57 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC ? 4C 8B E2 48 8B F1");

        NullFuncs.push_back(pattern);
    }
    else if (VersionInfo.EngineVersion >= 5.3)
    {
        auto pattern =
            Precision::Pattern("48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 4C 8B FA 48 8B F1 E8 ? ? ? ? 48 8B 0D");

        if (!pattern)
            pattern = Precision::Pattern("48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? "
                                                    "? 48 8B F2 4C 8B F1 E8 ? ? ? ? 48 8B 0D");

        NullFuncs.push_back(pattern);
    }
    else if (VersionInfo.EngineVersion == 4.27)
    {
        auto pattern = Precision::Pattern("48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 55 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC 70 4C 8B FA 4C");

        if (!pattern)
            pattern = Precision::Pattern("48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 55 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC ? 4C 8B FA 4C 8B F1 E8 ? ? ? ? 48 8B 0D");

        NullFuncs.push_back(pattern);
    }
    else
    {
        auto sRef = Precision::FindStringRefSmart(L"Changing GameSessionId from '%s' to '%s'");
        NullFuncs.push_back(Memcury::Scanner(sRef).ScanFor(VersionInfo.EngineVersion >= 4.27 ? std::vector<uint8>{ 0x48, 0x89, 0x5C } : std::vector<uint8>{ 0x40, 0x55 }, false, 0, 1, 2000).Get());
    }

    // if (VersionInfo.EngineVersion == 4.23)
    //     NullFuncs.push_back(Memcury::Scanner::FindPattern("48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 56 48 81 EC ? ? ? ? 0F B6 FA").Get());
    /*else if (VersionInfo.EngineVersion >= 4.24 && VersionInfo.EngineVersion < 4.27)
    {
        auto sRef = Memcury::Scanner::FindStringRef(L"STAT_CollectGarbageInternal").Get();
        uint64_t CollectGarbage = 0;

        if (!sRef)
            sRef = Memcury::Scanner::FindStringRef(L"CollectGarbageInternal() is flushing async loading").Get();

        if (sRef)
        {
            for (int i = 0; i < 1000; i++)
    {
                auto Ptr = (uint8_t*)(sRef - i);

                if (*Ptr == 0x48 && *(Ptr + 1) == 0x89 && *(Ptr + 2) == 0x5C)
    {
                    CollectGarbage = uint64_t(Ptr);
                    break;
                }
                else if (*Ptr == 0x40 && *(Ptr + 1) == 0x55)
    {
                    CollectGarbage = uint64_t(Ptr);
                    break;
                }
                else if (*Ptr == 0x48 && *(Ptr + 1) == 0x8B && *(Ptr + 2) == 0xC4)
    {
                    CollectGarbage = uint64_t(Ptr);
                    break;
                }
            }
            NullFuncs.push_back(CollectGarbage);
        }
    }*/

    if (VersionInfo.FortniteVersion == 1.10 || VersionInfo.FortniteVersion == 1.11 || (VersionInfo.FortniteVersion >= 2.2 && VersionInfo.FortniteVersion <= 2.4))
        RetTrueFuncs.push_back(Precision::Pattern("48 89 5C 24 ? 48 89 6C 24 ? 57 41 56 41 57 48 81 EC ? ? ? ? 48 8B 01 49 8B E9 45 0F B6 F8"));
    else if (VersionInfo.EngineVersion >= 4.26)
    {
        if (std::floor(VersionInfo.FortniteVersion) == 17)
        {
            auto pattern = Precision::Pattern("48 8B C4 48 89 58 08 48 89 70 10 48 89 78 18 4C 89 60 20 55 41 56 41 57 48 8B EC 48 83 EC 60 4D 8B F9 41 8A F0 4C 8B F2 48 8B F9 45 32 E4");

            if (pattern)
                RetTrueFuncs.push_back(pattern);
            else
                RetTrueFuncs.push_back(Precision::Pattern("48 8B C4 48 89 58 08 48 89 70 10 48 89 78 18 4C 89 60 20 55 41 56 41 57 48 8B EC 48 83 EC 60 49 8B D9 45 8A"));
        }
        else
            RetTrueFuncs.push_back(Precision::Pattern("48 8B C4 48 89 58 08 48 89 70 10 48 89 78 18 4C 89 60 20 55 41 56 41 57 48 8B EC 48 83 EC 60 49 8B D9 45 8A"));
    }
    RetTrueFuncs.push_back(FindKickPlayer());

    if (VersionInfo.FortniteVersion >= 23)
    {
        // NullFuncs.push_back(Memcury::Scanner::FindPattern("48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC ? 4C 8B E2 4C 8B F1").Get());
        // RetTrueFuncs.push_back(Memcury::Scanner::FindPattern("48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 49 8B F0 48 8B DA 48 85 D2 74 ? 48 83 BA").Get());
    }

    if (VersionInfo.FortniteVersion >= 16.00)
    {
        auto RequestExit =
            Precision::Pattern("40 53 48 83 EC ? 80 3D ? ? ? ? ? 0F B6 D9 72 ? 48 8D 05 ? ? ? ? 89 5C 24 ? 41 B9 ? ? ? ? 48 89 44 24 ? 4C 8D 05 ? ? ? ? 33 D2 33 C9 E8 ? ? ? ? 48 8D 0D");
        if (!RequestExit)
            RequestExit = Precision::Pattern("88 4C 24 ? 53 48 83 EC ? 80 3D ? ? ? ? ? 8A D9");
        if (!RequestExit)
            RequestExit = Precision::Pattern("40 53 48 83 EC ? 41 B9 ? ? ? ? 0F B6 D9");
        if (!RequestExit)
            RequestExit = Precision::Pattern("40 53 48 83 EC ? 80 3D ? ? ? ? ? 0F B6 D9");
        if (!RequestExit)
            RequestExit = Precision::Pattern("48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 33 DB 0F B6 F9");

        if (RequestExit)
            NullFuncs.push_back(RequestExit);

        auto RequestExitWithStatus = Precision::Pattern("48 89 5C 24 ? 57 48 83 EC 40 41 B9 ? ? ? ? 0F B6 F9 44 38 0D ? ? ? ? 0F B6 DA 72 24 89 5C 24 30 48 8D 05 ? "
                                                                   "? ? ? 89 7C 24 28 4C 8D 05 ? ? ? ? 33 D2 48 89 44 24 ? 33 C9 E8 ? ? ? ?");
        if (!RequestExitWithStatus)
            RequestExitWithStatus = Precision::Pattern("4C 8B DC 49 89 5B 08 49 89 6B 10 49 89 73 18 49 89 7B 20 41 56 48 83 EC 30 80 3D ? ? ? ? ? 49 8B");
        if (!RequestExitWithStatus)
            RequestExitWithStatus = Precision::Pattern("48 8B C4 48 89 58 18 88 50 10 88 48 08 57 48 83 EC 30");

        NullFuncs.push_back(RequestExitWithStatus);
    }

    if (VersionInfo.EngineVersion >= 4.21)
    {
        if (VersionInfo.EngineVersion == 4.21 || VersionInfo.EngineVersion == 4.22)
            RetTrueFuncs.push_back(Precision::Pattern("4C 89 4C 24 20 55 56 57 41 56 48 8D 6C 24 D1"));
        else
        {
            auto sRef = Precision::FindStringRefSmart(L"CanActivateAbility %s failed, blueprint refused");

            if (!sRef)
                sRef = Precision::FindStringRefSmart(L"CanActivateAbility %s failed, called with invalid Handle");

            if (sRef)
            {
                for (int i = 0; i < 0x2000; i++)
                {
                    auto Ptr = (uint8_t*)(sRef - i);

                    if (*Ptr == 0x48 && *(Ptr + 1) == 0x89 && *(Ptr + 2) == 0x5C)
                    {
                        RetTrueFuncs.push_back(uint64_t(Ptr));
                        break;
                    }
                    else if (*Ptr == 0x48 && *(Ptr + 1) == 0x8B && *(Ptr + 2) == 0xC4)
                    {
                        RetTrueFuncs.push_back(uint64_t(Ptr));
                        break;
                    }
                }
            }
        }
    }

    auto sRef = Precision::FindStringRefSmart(L"AFortPlayerControllerAthena::HasStreamingLevelsCompletedLoadingUnLoading(): %s still not visible");

    if (sRef)
    {
        for (int i = 0; i < 1000; i++)
        {
            auto Ptr = (uint8_t*)(sRef - i);

            if (*Ptr == 0x48 && *(Ptr + 1) == 0x89 && *(Ptr + 2) == 0x5C)
            {
                RetTrueFuncs.push_back(uint64_t(Ptr));
                break;
            }
            else if (*Ptr == 0x48 && *(Ptr + 1) == 0x8B && *(Ptr + 2) == 0xC4)
            {
                RetTrueFuncs.push_back(uint64_t(Ptr));
                break;
            }
        }
    }

    if (VersionInfo.FortniteVersion >= 23)
    {
        NullFuncs.push_back(Memcury::Scanner(Precision::FindStringRefSmart(L"STAT_FortCurieVoxelFirePropagationManager_IgniteGrassInBounds")).ScanFor({ 0x48, 0x8B, 0xC4 }, false).Get());
    }

    if (VersionInfo.EngineVersion < 5.0)
    {
        static const char* CanCreateSigs[] = {
            "8B ? E8 ? ? ? ? 84 C0 75 ? 80 3D ? ? ? ? 03 0F 82 ? ? ? ? ? 8B ? 18 ? 8D 54",
            "8B ? E8 ? ? ? ? 84 C0 0F 85 ? ? ? ? 80 3D ? ? ? ? 03 0F 82 ? ? ? ? ? 8B ? 18 ? 8D 54",
            "8B ? E8 ? ? ? ? 84 C0 75 ? 80 3D ? ? ? ? 03 72 ? ? 8B ? 18 ? 8D 54",
        };
        for (auto Sig : CanCreateSigs)
        {
            for (auto Hit : Precision::FindAllPatterns(Sig))
            {
                auto Target = Memcury::Scanner(Hit).RelativeOffset(3).Get();
                if (Target && Precision::InText(Target))
                {
                    if (auto Resolved = Precision::ResolveFuncStart(Target))
                        RetTrueFuncs.push_back(Resolved);
                    else
                        RetTrueFuncs.push_back(Target);
                    goto can_create_done;
                }
            }
        }
    can_create_done:;
    }
    else
    {
    }
}

uint64 FindStreamInMyBuilding()
{
    auto sRef = Precision::FindStringRefSmart(L"%s.%s trying to load invalid level %s");

    if (!sRef)
        return 0;

    uint64_t StreamInMyBuildingPart = 0;
    for (int i = 0; i < 0x10000; i++)
    {
        auto Ptr = (uint8_t*)(sRef - i);

        if (*Ptr == 0x48 && *(Ptr + 1) == 0x83 && *(Ptr + 2) == 0xEC)
        {
            StreamInMyBuildingPart = uint64_t(Ptr);
            break;
        }
        else if (*Ptr == 0x48 && *(Ptr + 1) == 0x81 && *(Ptr + 2) == 0xEC)
        {
            StreamInMyBuildingPart = uint64_t(Ptr);
            break;
        }
    }

    if (!StreamInMyBuildingPart)
        return 0;

    for (int i = 0; i < 2000; i++)
    {
        auto Ptr = (uint8_t*)(StreamInMyBuildingPart - i);

        if (*Ptr == 0x48 && *(Ptr + 1) == 0x8B && *(Ptr + 2) == 0xC4)
            return uint64_t(Ptr);
        else if (*Ptr == 0x48 && *(Ptr + 1) == 0x89 && *(Ptr + 2) == 0x5C)
            return uint64_t(Ptr);
        else if (*Ptr == 0x40 && *(Ptr + 1) == 0x55)
            return uint64_t(Ptr);
    }

    return 0;
}

uint64 FindCheckCheckpointHeartBeat()
{
    if (VersionInfo.FortniteVersion < 17)
        return 0;

    return Precision::Patterns({
        "48 89 5C 24 10 48 89 6C 24 20 56 57 41 54 41 56 41 57 48 81 EC ? ? ? ? 65 48 8B 04 25 ? ? ? ? 4C 8B F9",
        "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? 65 48 8B 04 25 ? ? ? ? 4C 8B E9",
        "48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 54 41 55 41 56 48 81 EC ? ? ? ? 65 48 8B 04 25",
    });
}

uint64 FindApplyHomebaseEffectsOnPlayerSetup()
{
    if (VersionInfo.EngineVersion >= 4.20)
        return 0;

    return Precision::Pattern("40 55 53 57 41 54 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 00 4C 8B");
}

uint64 FindRetFalse()
{
    if (VersionInfo.FortniteVersion < 25 || VersionInfo.FortniteVersion >= 28)
        return 0;

    return Precision::Pattern("48 89 5C ? ? 57 48 83 EC ? 48 8B D1 48 85 C9 74 ?");
}

uint64 FindNetModePatch()
{
    if (VersionInfo.FortniteVersion < 23)
        return 0;

    auto Hits = Precision::FindAllPatterns("48 8B 01 FF 90 ? ? ? ? 48 8B 8B ? ? ? ? 48 85 C9 74 ? 48 8B 01 FF 90 ? ? ? ? 48 8D 8B");
    for (auto Hit : Hits)
    {
        auto PatchPoint = Memcury::Scanner(Hit)
                              .ScanFor(VersionInfo.EngineVersion < 5.5 ? std::vector<uint8_t>{ 0x48, 0x89, 0x5C } : std::vector<uint8_t>{ 0x40, 0x53 }, false)
                              .ScanFor({ 0x83, 0xF8, 0x02 })
                              .Get();
        if (PatchPoint && Precision::InText(PatchPoint))
            return PatchPoint;
    }
    return 0;
}

uint64 FindCrashSomething()
{
    if (VersionInfo.FortniteVersion < 24.30)
        return 0;

    uint64_t Sig = 0;
    if (VersionInfo.EngineVersion == 5.3)
        Sig = Precision::Pattern("40 53 48 83 EC ? 48 8B DA 49 8B D0 E8 ? ? ? ? 48 85 C0 0F 85 ? ? ? ? 48 39 83");
    else
        Sig = Precision::Pattern("48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC ? 4C 8D B1 ? ? ? ? 33 DB 49 8D 7E");

    if (!Sig)
        Sig = Precision::Pattern("40 53 48 83 EC ? 48 8B DA 48 8B D1 48 81 C1 ? ? ? ? E8 ? ? ? ? 48 85 C0 74 ? 4C 8B 0B 45 33 C0");

    return Sig;
}

uint64 FindOverrideCosmeticLoadout()
{
    if (VersionInfo.FortniteVersion < 11 || VersionInfo.FortniteVersion >= 16)
        return 0;

    static const char* Sigs[] = {
        "4D 8B CD 4C 8D 45 ? 48 8B D6",
        "4D 8B CD 4C 8D 85 ? ? ? ? 48 8B D6",
        "4C 8D 45 ? 48 8B D3 48 8B CF E8 ? ? ? ? 0F B6 57",
        "4C 8D 45 ? 48 8B D3 48 8B CF E8 ? ? ? ? 0F B6 4F",
    };

    for (auto Sig : Sigs)
    {
        for (auto Hit : Precision::FindAllPatterns(Sig))
        {
            auto Call = Memcury::Scanner(Hit).ScanFor({ 0xE8 }).Get();
            if (!Call)
                continue;
            auto Target = Memcury::Scanner(Call).RelativeOffset(1).Get();
            if (Target && Precision::InText(Target))
            {
                if (auto Resolved = Precision::ResolveFuncStart(Target))
                    return Resolved;
                return Target;
            }
        }
    }
    return 0;
}

uint64 FindPedestalBeginPlay()
{
    auto PedestalBeginPlay = Precision::FindStringRefSmart(L"AFortTeamMemberPedestal::BeginPlay - Begun play on pedestal %s");
    if (!PedestalBeginPlay)
        return 0;

    for (int i = 0; i < 1000; i++)
    {
        auto Ptr = (uint8_t*)(PedestalBeginPlay - i);

        if (*Ptr == 0x48 && *(Ptr + 1) == 0x89 && *(Ptr + 2) == 0x5c)
            return uint64_t(Ptr);
        if (*Ptr == 0x40 && *(Ptr + 1) == 0x53 && *(Ptr + 2) == 0x41 && *(Ptr + 3) == 0x56)
            return uint64_t(Ptr);
    }

    return 0;
}

uint64 FindReadyToStartMatch()
{
    static const char* Classes[] = { "FortGameModeAthena", "FortGameMode", "GameModeBase", nullptr };
    static const char* Functions[] = { "ReadyToStartMatch", nullptr };
    return FindUFuncExec(Classes, Functions);
}

const UFunction* FindUFunction(const char* const* ClassNames, const char* const* FunctionNames)
{
    if (!ClassNames || !FunctionNames)
        return nullptr;

    for (int c = 0; ClassNames[c]; c++)
    {
        auto DefaultObj = DefaultObjImpl(ClassNames[c]);
        if (!DefaultObj)
            continue;

        for (int f = 0; FunctionNames[f]; f++)
        {
            auto Function = DefaultObj->GetFunction(FunctionNames[f]);
            if (Function)
                return Function;
        }
    }

    return nullptr;
}

uint64 FindUFuncExec(const char* const* ClassNames, const char* const* FunctionNames)
{
    auto Function = FindUFunction(ClassNames, FunctionNames);
    if (!Function || !Function->ExecFunction)
        return 0;

    return uint64_t(Function->ExecFunction);
}

uint64 FindUFuncImpl(const char* const* ClassNames, const char* const* FunctionNames)
{
    auto Function = FindUFunction(ClassNames, FunctionNames);
    if (!Function)
        return 0;

    auto Impl = Function->GetImpl();
    return Impl ? uint64_t(Impl) : 0;
}

uint32 FindUFuncVft(const char* const* ClassNames, const char* const* FunctionNames)
{
    auto Function = FindUFunction(ClassNames, FunctionNames);
    if (!Function)
        return 0;

    auto Index = Function->GetVTableIndex();
    if (Index == uint32(-1) || Index == 0)
        return 0;

    return Index;
}
