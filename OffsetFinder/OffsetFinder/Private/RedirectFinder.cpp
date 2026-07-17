#include "pch.h"

#include "../Public/RedirectFinder.h"

namespace
{
    IMAGE_SECTION_HEADER* GetSection(uint64_t moduleBase, const char* name)
    {
        auto dos = (IMAGE_DOS_HEADER*)moduleBase;
        auto nt = (IMAGE_NT_HEADERS*)(moduleBase + dos->e_lfanew);
        auto section = IMAGE_FIRST_SECTION(nt);

        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, section++)
        {
            if (strncmp((const char*)section->Name, name, 8) == 0)
                return section;
        }

        return nullptr;
    }

    bool CheckBytesUp(uint64_t base, int ind, std::initializer_list<uint8_t> bytes)
    {
        auto ptr = (uint8_t*)(base - ind);
        int i = 0;
        for (auto b : bytes)
        {
            if (ptr[i++] != b)
                return false;
        }
        return true;
    }

    // same approach as tellurium/starfall: hit the string, walk up to the start of the func
    uint64_t FindProcessRequestInModule(uint64_t moduleBase, bool bEos)
    {
        auto saved = ImageBase;
        ImageBase = moduleBase;

        uint64_t sref = Memcury::Scanner::FindStringRef(L"STAT_FCurlHttpRequest_ProcessRequest", false).Get();
        if (!sref)
            sref = Memcury::Scanner::FindStringRef(L"%p: request (easy handle:%p) has been added to threaded queue for processing", false).Get();
        if (!sref)
            sref = Memcury::Scanner::FindStringRef("STAT_FCurlHttpRequest_ProcessRequest", false).Get();

        ImageBase = saved;

        if (!sref)
            return 0;

        for (int i = 0; i < 2048; i++)
        {
            if (bEos)
            {
                if (CheckBytesUp(sref, i, { 0x48, 0x89, 0x5C }))
                    return sref - i;
            }
            else
            {
                if (CheckBytesUp(sref, i, { 0x4C, 0x8B, 0xDC }))
                    return sref - i;

                if (CheckBytesUp(sref, i, { 0x48, 0x8B, 0xC4 }))
                    return sref - i;

                if (CheckBytesUp(sref, i, { 0x48, 0x81, 0xEC }) || CheckBytesUp(sref, i, { 0x48, 0x83, 0xEC }))
                {
                    for (int x = 0; x < 50; x++)
                    {
                        if (CheckBytesUp(sref, i + x, { 0x40 }))
                            return sref - i - x;

                        if (CheckBytesUp(sref, i + x, { 0x4C, 0x8B, 0xDC }) || CheckBytesUp(sref, i + x, { 0x48, 0x8B, 0xC4 }) ||
                            CheckBytesUp(sref, i + x, { 0x48, 0x89, 0x5C }))
                            break;
                    }
                }
            }
        }

        return 0;
    }

    // find the vtable slot in .rdata that points at ProcessRequest
    uint64_t FindProcessRequestVftSlot(uint64_t moduleBase, uint64_t processRequest)
    {
        if (!processRequest)
            return 0;

        auto rdata = GetSection(moduleBase, ".rdata");
        if (!rdata)
            return 0;

        auto start = (uint8_t*)(moduleBase + rdata->VirtualAddress);
        auto size = rdata->Misc.VirtualSize;

        for (uint32_t i = 0; i + 8 <= size; i += 8)
        {
            if (*(uint64_t*)(start + i) == processRequest)
                return uint64_t(start + i);
        }

        return 0;
    }

    uint64_t ScanFirst(std::initializer_list<const char*> patterns)
    {
        for (auto p : patterns)
        {
            auto addr = Memcury::Scanner::FindPattern(p).Get();
            if (addr)
                return addr;
        }
        return 0;
    }

    void PushIfFound(std::vector<RedirectFinders::Result>& out, const char* name, uint64_t absolute, bool isVft = false, bool relativeToEos = false)
    {
        if (!absolute)
            return;

        out.push_back({ name, absolute, isVft, relativeToEos });
    }
}

std::vector<RedirectFinders::Result> RedirectFinders::FindAll(uint64_t& eosBase)
{
    std::vector<Result> out;
    eosBase = 0;

    // tellurium realloc sig
    PushIfFound(out, "Realloc", Memcury::Scanner::FindPattern("48 89 5C 24 08 48 89 74 24 10 57 48 83 EC ? 48 8B F1 41 8B D8 48 8B 0D ? ? ? ?").Get());

    const uint64_t processRequest = FindProcessRequestInModule(ImageBase, false);
    PushIfFound(out, "CurlHttpInternalProcessRequest", processRequest);
    PushIfFound(out, "ProcessRequest", processRequest);

    const uint64_t processRequestVft = FindProcessRequestVftSlot(ImageBase, processRequest);
    PushIfFound(out, "ProcessRequestVft", processRequestVft);

    // used on eos builds to decide whether to apply the exit patches
    const uint64_t pushWidget = ScanFirst({
        "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 30 48 8B E9 49 8B D9 48 8D 0D ? ? ? ? 49 8B F8 48 8B F2 E8 ? ? ? ? 4C 8B CF 48 89 5C 24 ? 4C 8B C6 48 8B D5 48 8B 48 78",
        "48 8B C4 4C 89 40 18 48 89 50 10 48 89 48 08 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 68 B8 48 81 EC ? ? ? ? 65 48 8B 04 25",
        "48 8B C4 48 89 58 ? 48 89 70 ? 48 89 78 ? 55 41 56 41 57 48 8D 68 A1 48 81 EC ? ? ? ? 65 48 8B 04 25 ? ? ? ? 48 8B F9 B9 ? ? ? ?",
        "48 89 5C 24 ? 48 89 74 24 ? 55 57 41 54 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 49 8B D9 49 8B F8 4C 8B E2 4C 8B F1",
    });
    PushIfFound(out, "PushWidget", pushWidget);

    const uint64_t requestExit = ScanFirst({
        "48 89 5C 24 ? 57 48 83 EC 40 41 B9 ? ? ? ? 0F B6 F9 44 38 0D ? ? ? ? 0F B6 DA 72 24 89 5C 24 30 48 8D 05 ? ? ? ? 89 7C 24 28 4C 8D 05 ? ? ? ? 33 D2 48 89 44 24 ? 33 C9 E8 ? ? ? ?",
        "48 8B C4 48 89 58 18 88 50 10 88 48 08 57 48 83 EC 30",
        "4C 8B DC 49 89 5B 08 49 89 6B 10 49 89 73 18 49 89 7B 20 41 56 48 83 EC 30 80 3D ? ? ? ? ? 49 8B",
    });
    PushIfFound(out, "RequestExitWithStatus", requestExit);
    PushIfFound(out, "PatchRequestExit", requestExit);

    // unsafe env popup (patch this to ret)
    const uint64_t unsafeEnv = ScanFirst({
        "4C 8B DC 55 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 49 89 73 F0 49 89 7B E8 48 8B F9 4D 89 63 E0 4D 8B E0 4D 89 6B D8",
        "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 ? 41 0F B6 D8 48 89 55 ? 88 5C 24 ?",
        "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 80 B9 ? ? ? ? ? 48 8B DA 48 8B F1",
        "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? ? 0F B6 ? 44 88 44 24 ?",
        "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 ? 45 0F B6 F8",
        "40 55 53 56 57 41 54 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? ? 0F B6 ?",
        "4C 8B DC 55 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ?",
    });
    PushIfFound(out, "ShowAppEnvironmentSecurityMessage", unsafeEnv);
    PushIfFound(out, "PatchUnsafeEnvironment", unsafeEnv);

    // starfall memleak stuff (just ret 0)
    PushIfFound(out, "MemLeakFix1", Memcury::Scanner::FindPattern("48 8B 01 4C 8D 41 08 48 FF 60 20").Get());
    PushIfFound(out, "MemLeakFix2", Memcury::Scanner::FindPattern("48 89 5C 24 ?? 57 48 83 EC ?? 48 8B 01 4C 8B C2 48 8D 54 24").Get());

    // starfall falls back to 10 if it cant resolve SetURL dynamically
    PushIfFound(out, "SetURLVft", 10, true, false);

    // eos if its loaded
    HMODULE eos = GetModuleHandleA("EOSSDK-Win64-Shipping.dll");
    if (!eos)
        eos = LoadLibraryA("EOSSDK-Win64-Shipping.dll");

    if (eos)
    {
        eosBase = uint64_t(eos);
        const uint64_t eosProcessRequest = FindProcessRequestInModule(eosBase, true);
        PushIfFound(out, "CurlHttpInternalProcessRequestEOS", eosProcessRequest, false, true);
        PushIfFound(out, "ProcessRequestEOS", eosProcessRequest, false, true);
        PushIfFound(out, "ProcessRequestEOSVft", FindProcessRequestVftSlot(eosBase, eosProcessRequest), false, true);
    }

    return out;
}
