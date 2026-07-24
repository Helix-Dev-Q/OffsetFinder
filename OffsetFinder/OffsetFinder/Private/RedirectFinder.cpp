#include "pch.h"

#include "../Public/RedirectFinder.h"
#include "../Public/Precision.h"

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

    bool InRange(uint64_t value, uint64_t start, uint64_t end)
    {
        return value >= start && value < end;
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

    bool CheckBytesAt(uint64_t func, int off, std::initializer_list<uint8_t> bytes)
    {
        auto ptr = (uint8_t*)(func + off);
        int i = 0;
        for (auto b : bytes)
        {
            if (ptr[i++] != b)
                return false;
        }
        return true;
    }

    bool LooksLikeUrlField(uint32_t off)
    {
        return off >= 0x80 && off < 0x400 && (off % 8) == 0;
    }

    bool LooksLikeBlockFlag(uint32_t off, uint32_t urlField)
    {
        return off != urlField && off >= 0x20 && off < 0x400;
    }

    uint32_t GetImageSize(uint64_t moduleBase)
    {
        auto dos = (IMAGE_DOS_HEADER*)moduleBase;
        auto nt = (IMAGE_NT_HEADERS*)(moduleBase + dos->e_lfanew);
        return nt->OptionalHeader.SizeOfImage;
    }

    uint64_t FindVftSlotForFunc(uint64_t moduleBase, uint64_t func)
    {
        if (!func)
            return 0;

        auto text = GetSection(moduleBase, ".text");
        if (!text)
            return 0;

        const uint64_t textStart = moduleBase + text->VirtualAddress;
        const uint64_t textEnd = textStart + text->Misc.VirtualSize;
        const uint32_t imageSize = GetImageSize(moduleBase);
        auto bytes = (uint8_t*)moduleBase;

        uint64_t best = 0;
        int bestScore = -1;

        for (uint32_t i = 0; i + 8 <= imageSize; i += 8)
        {
            const uint64_t addr = moduleBase + i;
            if (InRange(addr, textStart, textEnd))
                continue;

            if (*(uint64_t*)(bytes + i) != func)
                continue;

            int score = 0;
            for (int k = 1; k <= 12; k++)
            {
                if (i < (uint32_t)k * 8)
                    break;
                const uint64_t prev = *(uint64_t*)(bytes + i - k * 8);
                if (InRange(prev, textStart, textEnd))
                    score++;
            }

            if (score > bestScore)
            {
                bestScore = score;
                best = addr;
                if (score >= 4)
                    return best;
            }
        }

        return best;
    }

    uint64_t ResolveProcessRequestStart(uint64_t sref, bool bEos)
    {
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

    void CollectLeaRefsTo(uint64_t moduleBase, uint64_t target, std::vector<uint64_t>& out)
    {
        auto text = GetSection(moduleBase, ".text");
        if (!text || !target)
            return;

        auto start = (uint8_t*)(moduleBase + text->VirtualAddress);
        const uint32_t size = text->Misc.VirtualSize;

        for (uint32_t i = 0; i + 7 < size; i++)
        {
            if ((start[i] != 0x48 && start[i] != 0x4C) || start[i + 1] != 0x8D)
                continue;

            const uint8_t modrm = start[i + 2];
            if ((modrm & 0xC7) != 0x05) // mod=00 rm=101 => rip-relative
                continue;

            const int32_t disp = *(int32_t*)(start + i + 3);
            const uint64_t rip = uint64_t(start + i + 7);
            if (rip + disp == target)
                out.push_back(uint64_t(start + i));
        }
    }

    uint64_t FindDataStringW(uint64_t moduleBase, const wchar_t* str)
    {
        if (!str)
            return 0;

        const size_t bytes = (wcslen(str) + 1) * sizeof(wchar_t);
        auto rdata = GetSection(moduleBase, ".rdata");
        if (rdata)
        {
            auto start = (uint8_t*)(moduleBase + rdata->VirtualAddress);
            const uint32_t size = rdata->Misc.VirtualSize;
            for (uint32_t i = 0; i + bytes <= size; i += 2)
            {
                if (memcmp(start + i, str, bytes) == 0)
                    return uint64_t(start + i);
            }
        }

        auto img = (uint8_t*)moduleBase;
        const uint32_t imageSize = GetImageSize(moduleBase);
        for (uint32_t i = 0; i + bytes <= imageSize; i += 2)
        {
            if (memcmp(img + i, str, bytes) == 0)
                return moduleBase + i;
        }
        return 0;
    }

    uint64_t FindDataStringA(uint64_t moduleBase, const char* str)
    {
        if (!str)
            return 0;

        const size_t bytes = strlen(str) + 1;
        auto rdata = GetSection(moduleBase, ".rdata");
        if (rdata)
        {
            auto start = (uint8_t*)(moduleBase + rdata->VirtualAddress);
            const uint32_t size = rdata->Misc.VirtualSize;
            for (uint32_t i = 0; i + bytes <= size; i++)
            {
                if (memcmp(start + i, str, bytes) == 0)
                    return uint64_t(start + i);
            }
        }
        return 0;
    }

    bool FindProcessRequestAndVft(uint64_t moduleBase, bool bEos, uint64_t& outFunc, uint64_t& outVftSlot)
    {
        outFunc = 0;
        outVftSlot = 0;

        std::vector<uint64_t> stringAddrs;
        if (auto s = FindDataStringW(moduleBase, L"STAT_FCurlHttpRequest_ProcessRequest"))
            stringAddrs.push_back(s);
        if (auto s = FindDataStringW(moduleBase, L"%p: request (easy handle:%p) has been added to threaded queue for processing"))
            stringAddrs.push_back(s);
        if (auto s = FindDataStringA(moduleBase, "STAT_FCurlHttpRequest_ProcessRequest"))
            stringAddrs.push_back(s);

        std::vector<uint64_t> leaRefs;
        for (auto strAddr : stringAddrs)
            CollectLeaRefsTo(moduleBase, strAddr, leaRefs);

        {
            auto saved = ImageBase;
            ImageBase = moduleBase;
            if (auto sref = Memcury::Scanner::FindStringRef(L"STAT_FCurlHttpRequest_ProcessRequest", false, 0, Precision::UseUE51StringRefs()).Get())
                leaRefs.push_back(sref);
            if (auto sref = Memcury::Scanner::FindStringRef(L"%p: request (easy handle:%p) has been added to threaded queue for processing", false, 0, Precision::UseUE51StringRefs()).Get())
                leaRefs.push_back(sref);
            ImageBase = saved;
        }

        uint64_t BestFunc = 0;
        uint64_t BestSlot = 0;
        int BestScore = -1;

        for (auto sref : leaRefs)
        {
            const uint64_t fn = ResolveProcessRequestStart(sref, bEos);
            if (!fn)
                continue;

            const uint64_t slot = FindVftSlotForFunc(moduleBase, fn);
            int Score = 0;
            if (slot)
                Score += 50;
            if (Precision::IsPrologue((uint8_t*)fn))
                Score += 10;
            if (fn > moduleBase && Precision::LooksLikeFuncBoundaryByte(*((uint8_t*)fn - 1)))
                Score += 5;

            Score += 1;

            if (Score > BestScore)
            {
                BestScore = Score;
                BestFunc = fn;
                BestSlot = slot;
            }
        }

        outFunc = BestFunc;
        outVftSlot = BestSlot ? BestSlot : FindVftSlotForFunc(moduleBase, BestFunc);
        return outFunc != 0;
    }

    bool TryReadRcxDisp(uint8_t* p, uint32_t& outOff)
    {
        if ((p[0] == 0x48 || p[0] == 0x4C) && (p[1] == 0x8D || p[1] == 0x8B))
        {
            const uint8_t modrm = p[2];
            if ((modrm & 0xC7) == 0x81) // mod=10, rm=rcx
            {
                outOff = *(uint32_t*)(p + 3);
                return true;
            }
            if ((modrm & 0xC7) == 0x41) // mod=01, rm=rcx, imm8
            {
                outOff = (uint32_t)(int32_t)(int8_t)p[3];
                return true;
            }
        }

        if (p[0] == 0x48 && p[1] == 0x81 && p[2] == 0xC1)
        {
            outOff = *(uint32_t*)(p + 3);
            return true;
        }

        if (p[0] == 0x48 && p[1] == 0x8D && p[2] == 0x91)
        {
            outOff = *(uint32_t*)(p + 3);
            return true;
        }

        return false;
    }

    uint32_t FindUrlFieldInFunc(uint64_t func, int scanLen = 0x200)
    {
        if (!func)
            return 0;

        for (int i = 0; i < scanLen; i++)
        {
            uint32_t off = 0;
            if (!TryReadRcxDisp((uint8_t*)(func + i), off))
                continue;
            if (LooksLikeUrlField(off))
                return off;
        }
        return 0;
    }

    uint32_t FindUrlFieldFromVtable(uint64_t moduleBase, uint64_t processRequestSlot, uint64_t* outGetUrl = nullptr, uint64_t* outVtable = nullptr)
    {
        if (!processRequestSlot)
            return 0;

        auto text = GetSection(moduleBase, ".text");
        auto rdata = GetSection(moduleBase, ".rdata");
        if (!text || !rdata)
            return 0;

        const uint64_t textStart = moduleBase + text->VirtualAddress;
        const uint64_t textEnd = textStart + text->Misc.VirtualSize;
        const uint64_t rdataStart = moduleBase + rdata->VirtualAddress;
        const uint64_t rdataEnd = rdataStart + rdata->Misc.VirtualSize;

        uint64_t* slot = (uint64_t*)processRequestSlot;

        uint32_t bestUrl = 0;
        uint64_t bestFn = 0;
        uint64_t bestBase = 0;

        for (int i = 0; i < 64; i++)
        {
            uint64_t* candidateSlot = slot - i;
            if ((uint64_t)candidateSlot < rdataStart || (uint64_t)candidateSlot >= rdataEnd)
                break;

            const uint64_t fn = *candidateSlot;
            if (!fn)
                continue;
            if (!InRange(fn, textStart, textEnd))
                break;

            const uint32_t url = FindUrlFieldInFunc(fn, 0x100);
            if (url)
            {
                bestUrl = url;
                bestFn = fn;
                bestBase = (uint64_t)candidateSlot;
            }
        }

        if (bestBase)
        {
            uint64_t* base = (uint64_t*)bestBase;
            while ((uint64_t)(base - 1) >= rdataStart && InRange(*(base - 1), textStart, textEnd))
                base--;
            bestBase = (uint64_t)base;
        }

        if (outGetUrl)
            *outGetUrl = bestFn;
        if (outVtable)
            *outVtable = bestBase;

        return bestUrl;
    }

    uint64_t FindSetURLInVtable(uint64_t vtable, uint32_t urlField, uint64_t processRequestSlot, int64_t* outIdx = nullptr)
    {
        if (!vtable || !urlField)
            return 0;

        int64_t maxIdx = 0x40;
        if (processRequestSlot > vtable)
            maxIdx = int64_t((processRequestSlot - vtable) / 8) + 1;
        if (maxIdx < 2)
            maxIdx = 0x40;
        if (maxIdx > 0x50)
            maxIdx = 0x50;

        for (int64_t i = 1; i < maxIdx; i++)
        {
            const uint64_t func = *(uint64_t*)(vtable + i * 8);
            if (!func)
                continue;

            for (int j = 0; j < 0x80; j++)
            {
                uint32_t off = 0;
                if (!TryReadRcxDisp((uint8_t*)(func + j), off))
                    continue;
                if (off != urlField)
                    continue;

                if (CheckBytesAt(func, j, { 0x48, 0x81, 0xC1 }) || CheckBytesAt(func, j, { 0x48, 0x8D, 0x89 }))
                {
                    if (outIdx)
                        *outIdx = i;
                    return func;
                }
            }
        }

        for (int64_t i = 1; i < maxIdx; i++)
        {
            const uint64_t func = *(uint64_t*)(vtable + i * 8);
            if (!func)
                continue;

            for (int j = 0; j < 0x80; j++)
            {
                uint32_t off = 0;
                if (TryReadRcxDisp((uint8_t*)(func + j), off) && off == urlField)
                {
                    if (outIdx)
                        *outIdx = i;
                    return func;
                }
            }
        }

        return 0;
    }

    uint64_t FindSetURLInText(uint64_t moduleBase, uint32_t urlField)
    {
        if (!urlField)
            return 0;

        auto text = GetSection(moduleBase, ".text");
        if (!text)
            return 0;

        auto start = (uint8_t*)(moduleBase + text->VirtualAddress);
        const uint32_t size = text->Misc.VirtualSize;

        uint8_t needleAdd[7] = { 0x48, 0x81, 0xC1, 0, 0, 0, 0 };
        memcpy(needleAdd + 3, &urlField, 4);

        uint8_t needleLea[7] = { 0x48, 0x8D, 0x89, 0, 0, 0, 0 };
        memcpy(needleLea + 3, &urlField, 4);

        for (uint32_t i = 0; i + 7 < size; i++)
        {
            if (memcmp(start + i, needleAdd, 7) != 0 && memcmp(start + i, needleLea, 7) != 0)
                continue;

            uint64_t hit = uint64_t(start + i);
            for (int back = 0; back < 0x80; back++)
            {
                auto p = (uint8_t*)(hit - back);
                if (p[0] == 0x48 && p[1] == 0x89 && p[2] == 0x5C) // mov [rsp+..], rbx
                    return hit - back;
                if (p[0] == 0x40 && (p[1] == 0x53 || p[1] == 0x55 || p[1] == 0x56 || p[1] == 0x57))
                    return hit - back;
                if (p[0] == 0x48 && p[1] == 0x8B && p[2] == 0xC4)
                    return hit - back;
            }
            return hit;
        }

        return 0;
    }

    uint32_t FindUrlSetBlockFlag(uint64_t setUrl, uint32_t urlField)
    {
        if (!setUrl)
            return 0;

        for (int i = 0; i < 0x280; i++)
        {
            auto p = (uint8_t*)(setUrl + i);

            if (p[0] == 0xC7 && p[1] == 0x81 && *(uint32_t*)(p + 6) == 0)
            {
                const uint32_t off = *(uint32_t*)(p + 2);
                if (LooksLikeBlockFlag(off, urlField))
                    return off;
            }

            if (p[0] == 0xC6 && p[1] == 0x81 && p[6] == 0)
            {
                const uint32_t off = *(uint32_t*)(p + 2);
                if (LooksLikeBlockFlag(off, urlField))
                    return off;
            }

            if (p[0] == 0x83 && p[1] == 0xB9 && p[6] == 0)
            {
                const uint32_t off = *(uint32_t*)(p + 2);
                if (LooksLikeBlockFlag(off, urlField))
                    return off;
            }

            if (p[0] == 0x80 && p[1] == 0xB9 && p[6] == 0)
            {
                const uint32_t off = *(uint32_t*)(p + 2);
                if (LooksLikeBlockFlag(off, urlField))
                    return off;
            }

            if (p[0] == 0xF6 && p[1] == 0x81)
            {
                const uint32_t off = *(uint32_t*)(p + 2);
                if (LooksLikeBlockFlag(off, urlField))
                    return off;
            }
            if (p[0] == 0x83 && p[1] == 0xB9)
            {
                const uint32_t off = *(uint32_t*)(p + 2);
                if (LooksLikeBlockFlag(off, urlField))
                    return off;
            }

            if (p[0] == 0xC7 && p[1] == 0x41 && *(uint32_t*)(p + 3) == 0)
            {
                const uint32_t off = p[2];
                if (LooksLikeBlockFlag(off, urlField))
                    return off;
            }
            if (p[0] == 0x83 && p[1] == 0x79 && p[3] == 0)
            {
                const uint32_t off = p[2];
                if (LooksLikeBlockFlag(off, urlField))
                    return off;
            }
            if (p[0] == 0x80 && p[1] == 0x79 && p[3] == 0)
            {
                const uint32_t off = p[2];
                if (LooksLikeBlockFlag(off, urlField))
                    return off;
            }
            if (p[0] == 0xF6 && p[1] == 0x41)
            {
                const uint32_t off = p[2];
                if (LooksLikeBlockFlag(off, urlField))
                    return off;
            }
        }

        return 0;
    }

    uint64_t ScanPattern(const char* pattern)
    {
        return Precision::Pattern(pattern);
    }

    uint64_t FindPushWidget()
    {
        constexpr const char* PatLegacy =
            "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 30 48 8B E9 49 8B D9 48 8D 0D ? ? ? ? 49 8B F8 48 8B F2 E8 ? ? ? ? 4C 8B CF 48 89 5C 24 ? 4C 8B C6 48 8B D5 48 8B 48 78";
        constexpr const char* Pat26 =
            "48 8B C4 4C 89 40 18 48 89 50 10 48 89 48 08 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 68 B8 48 81 EC ? ? ? ? 65 48 8B 04 25";
        constexpr const char* Pat28_30 =
            "48 8B C4 48 89 58 ? 48 89 70 ? 48 89 78 ? 55 41 56 41 57 48 8D 68 A1 48 81 EC ? ? ? ? 65 48 8B 04 25 ? ? ? ? 48 8B F9 B9 ? ? ? ?";
        constexpr const char* PatAltLegacy =
            "48 89 5C 24 ? 48 89 74 24 ? 55 57 41 54 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 49 8B D9 49 8B F8 4C 8B E2 4C 8B F1";

        const double FN = VersionInfo.FortniteVersion;
        if (FN >= 28.00)
            return ScanPattern(Pat28_30);
        if (FN >= 26.00)
            return ScanPattern(Pat26);

        return Precision::Patterns({ PatLegacy, PatAltLegacy });
    }

    uint64_t FindUnsafeEnvironmentPopup()
    {
        const double FN = VersionInfo.FortniteVersion;

        constexpr const char* Pat1910 =
            "4C 8B DC 55 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 49 89 73 F0 49 89 7B E8 48 8B F9 4D 89 63 E0 4D 8B E0 4D 89 6B D8";
        constexpr const char* PatAlt =
            "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 ? 41 0F B6 D8 48 89 55 ? 88 5C 24 ?";
        constexpr const char* Pat30 =
            "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 80 B9 ? ? ? ? ? 48 8B DA 48 8B F1";
        constexpr const char* Pat28 =
            "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? ? 0F B6 ? 44 88 44 24 ?";
        constexpr const char* Pat2830 =
            "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 ? 45 0F B6 F8";
        constexpr const char* Pat29_2240 =
            "40 55 53 56 57 41 54 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? ? 0F B6 ?";
        constexpr const char* PatBroad =
            "4C 8B DC 55 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ?";

        if (FN >= 19.00 && FN < 20.00)
            return ScanPattern(Pat1910);
        if (FN >= 28.30 && FN < 29.00)
            return ScanPattern(Pat2830);
        if (std::floor(FN) == 28)
            return ScanPattern(Pat28);
        if (FN >= 30.00)
            return ScanPattern(Pat30);
        if ((FN >= 22.00 && FN < 23.00) || (FN >= 29.00 && FN < 30.00))
            return ScanPattern(Pat29_2240);

        return Precision::Patterns({ PatAlt, PatBroad });
    }

    uint64_t FindRequestExitWithStatus()
    {
        return Precision::Patterns({
            "48 89 5C 24 ? 57 48 83 EC 40 41 B9 ? ? ? ? 0F B6 F9 44 38 0D ? ? ? ? 0F B6 DA 72 24 89 5C 24 30 48 8D 05 ? ? ? ? 89 7C 24 28 4C 8D 05 ? ? ? ? 33 D2 48 89 44 24 ? 33 C9 E8 ? ? ? ?",
            "48 8B C4 48 89 58 18 88 50 10 88 48 08 57 48 83 EC 30",
            "4C 8B DC 49 89 5B 08 49 89 6B 10 49 89 73 18 49 89 7B 20 41 56 48 83 EC 30 80 3D ? ? ? ? ? 49 8B",
        });
    }

    bool ResolveSetURLFromGetURL(uint64_t vtable, uint64_t processRequestSlot,
        uint32_t& outUrlField, uint64_t& outGetUrl, uint64_t& outSetUrl, int64_t& outSetUrlIdx)
    {
        outUrlField = 0;
        outGetUrl = 0;
        outSetUrl = 0;
        outSetUrlIdx = 0;

        if (!vtable)
            return false;

        outGetUrl = *(uint64_t*)vtable;
        if (!outGetUrl)
            return false;

        for (int i = 0; i < 100; i++)
        {
            auto P = (uint8_t*)(outGetUrl + i);
            if (P[0] == 0x48 && P[1] == 0x8D && P[2] == 0x91)
            {
                outUrlField = *(uint32_t*)(P + 3);
                break;
            }
        }

        if (!outUrlField)
            return false;

        int64_t maxIdx = 0x20;
        if (processRequestSlot > vtable)
        {
            maxIdx = int64_t((processRequestSlot - vtable) / 8);
            if (maxIdx < 2)
                maxIdx = 0x20;
            if (maxIdx > 0x40)
                maxIdx = 0x40;
        }

        for (int64_t i = 1; i < maxIdx; i++)
        {
            const uint64_t Func = *(uint64_t*)(vtable + i * 8);
            if (!Func)
                continue;

            for (int j = 0; j < 0x20; j++)
            {
                auto P = (uint8_t*)(Func + j);
                if (P[0] == 0x48 && P[1] == 0x81 && P[2] == 0xC1 && *(uint32_t*)(P + 3) == outUrlField)
                {
                    outSetUrl = Func;
                    outSetUrlIdx = i;
                    return true;
                }
            }
        }

        return false;
    }

    bool HasName(const std::vector<RedirectFinders::Result>& out, const char* name)
    {
        for (auto& e : out)
        {
            if (e.Name && strcmp(e.Name, name) == 0)
                return true;
        }
        return false;
    }

    void PushIfFound(std::vector<RedirectFinders::Result>& out, const char* name, uint64_t absolute,
        bool isVft = false, bool relativeToEos = false, bool isMemberOffset = false)
    {
        if (!absolute || !name)
            return;
        if (HasName(out, name))
            return;

        out.push_back({ name, absolute, isVft, relativeToEos, isMemberOffset });
    }

    void LogHit(const char* name, uint64_t value, uint64_t base = 0, bool memberOrVft = false, bool eos = false)
    {
        if (!value)
        {
            printf("  %-40s NOT FOUND\n", name);
            return;
        }
        if (memberOrVft)
            printf("  %-40s 0x%llX\n", name, value);
        else if (eos)
            printf("  %-40s EOS+0x%llX\n", name, value - base);
        else
            printf("  %-40s 0x%llX\n", name, value - base);
    }

    uint64_t FindFStringAssign(uint64_t moduleBase, uint64_t setUrl, uint32_t urlField)
    {
        if (!setUrl || !urlField)
            return 0;

        auto text = GetSection(moduleBase, ".text");
        if (!text)
            return 0;

        const uint64_t textStart = moduleBase + text->VirtualAddress;
        const uint64_t textEnd = textStart + text->Misc.VirtualSize;

        int urlTouch = -1;
        for (int i = 0; i < 0x300; i++)
        {
            uint32_t off = 0;
            if (!TryReadRcxDisp((uint8_t*)(setUrl + i), off) || off != urlField)
                continue;
            urlTouch = i;
            break;
        }
        if (urlTouch < 0)
            return 0;

        for (int i = urlTouch; i < urlTouch + 0x80 && i < 0x300; i++)
        {
            auto p = (uint8_t*)(setUrl + i);
            if (p[0] != 0xE8)
                continue;

            const int32_t rel = *(int32_t*)(p + 1);
            const uint64_t target = setUrl + i + 5 + rel;
            if (InRange(target, textStart, textEnd))
                return target;
        }

        return 0;
    }

    void FindCurlHttpRequestFields(std::vector<RedirectFinders::Result>& out, uint64_t moduleBase,
        uint64_t processRequest, uint64_t processRequestSlot, bool bEos)
    {
        const char* urlName = bEos ? "EosUrlField" : "UrlField";

        uint64_t getUrl = 0;
        uint64_t vtable = 0;
        uint32_t urlField = 0;
        uint64_t setUrl = 0;
        int64_t setUrlIdx = 0;

        if (processRequestSlot)
        {
            auto text = GetSection(moduleBase, ".text");
            auto rdata = GetSection(moduleBase, ".rdata");
            if (text && rdata)
            {
                const uint64_t textStart = moduleBase + text->VirtualAddress;
                const uint64_t textEnd = textStart + text->Misc.VirtualSize;
                const uint64_t rdataStart = moduleBase + rdata->VirtualAddress;

                uint64_t* base = (uint64_t*)processRequestSlot;
                while ((uint64_t)(base - 1) >= rdataStart && InRange(*(base - 1), textStart, textEnd))
                    base--;
                vtable = (uint64_t)base;

                uint32_t tellUrl = 0;
                uint64_t tellGet = 0, tellSet = 0;
                int64_t tellIdx = 0;
                const bool foundSet = ResolveSetURLFromGetURL(vtable, processRequestSlot, tellUrl, tellGet, tellSet, tellIdx);
                if (tellUrl)
                {
                    urlField = tellUrl;
                    getUrl = tellGet;
                    if (foundSet)
                    {
                        setUrl = tellSet;
                        setUrlIdx = tellIdx;
                    }
                }
            }
        }

        if (!urlField)
        {
            urlField = FindUrlFieldFromVtable(moduleBase, processRequestSlot, &getUrl, &vtable);
            if (!urlField && processRequest)
                urlField = FindUrlFieldInFunc(processRequest, 0xC00);
        }

        if (urlField)
            PushIfFound(out, urlName, urlField, false, false, true);
        LogHit(urlName, urlField, 0, true);

        if (getUrl && !bEos)
        {
            PushIfFound(out, "GetURL", getUrl);
            LogHit("GetURL", getUrl, moduleBase);
        }

        if (bEos)
            return;

        if (!setUrl && urlField)
        {
            setUrl = FindSetURLInVtable(vtable, urlField, processRequestSlot, &setUrlIdx);
            if (!setUrl)
                setUrl = FindSetURLInText(moduleBase, urlField);
        }

        if (setUrl)
        {
            PushIfFound(out, "SetURL", setUrl);
            LogHit("SetURL", setUrl, moduleBase);
        }
        else
        {
            LogHit("SetURL", 0);
        }

        if (!setUrlIdx)
            setUrlIdx = 10;
        PushIfFound(out, "SetURLVft", uint64_t(setUrlIdx), true);
        LogHit("SetURLVft", uint64_t(setUrlIdx), 0, true);

        const uint32_t blockFlag = FindUrlSetBlockFlag(setUrl, urlField);
        if (blockFlag)
            PushIfFound(out, "UrlSetBlockFlag", blockFlag, false, false, true);
        LogHit("UrlSetBlockFlag", blockFlag, 0, true);

        const uint64_t fstringAssign = FindFStringAssign(moduleBase, setUrl, urlField);
        if (fstringAssign)
            PushIfFound(out, "FStringAssign", fstringAssign);
        LogHit("FStringAssign", fstringAssign, moduleBase);
    }
}

std::vector<RedirectFinders::Result> RedirectFinders::FindAll(uint64_t& eosBase)
{
    std::vector<Result> out;
    eosBase = 0;

    printf("\n--- redirect offsets ---\n");

    uint64_t reallocAddr = Precision::Pattern("48 89 5C 24 08 48 89 74 24 10 57 48 83 EC ? 48 8B F1 41 8B D8 48 8B 0D ? ? ? ?");
    if (!reallocAddr && SDK::Offsets::Realloc)
        reallocAddr = SDK::Offsets::Realloc;
    PushIfFound(out, "Realloc", reallocAddr);
    PushIfFound(out, "FMemoryRealloc", reallocAddr);
    LogHit("Realloc", reallocAddr, ImageBase);

    if (SDK::Offsets::AppendString)
    {
        PushIfFound(out, "AppendString", SDK::Offsets::AppendString);
        LogHit("AppendString", SDK::Offsets::AppendString, ImageBase);
    }
    if (SDK::Offsets::ToString)
    {
        PushIfFound(out, "ToString", SDK::Offsets::ToString);
        LogHit("ToString", SDK::Offsets::ToString, ImageBase);
    }

    uint64_t processRequest = 0;
    uint64_t processRequestVft = 0;
    FindProcessRequestAndVft(ImageBase, false, processRequest, processRequestVft);

    PushIfFound(out, "CurlHttpInternalProcessRequest", processRequest);
    PushIfFound(out, "ProcessRequest", processRequest);
    PushIfFound(out, "ProcessRequestVft", processRequestVft);
    PushIfFound(out, "ProcessRequestVtableSlot", processRequestVft);

    LogHit("ProcessRequest", processRequest, ImageBase);
    LogHit("ProcessRequestVft", processRequestVft, ImageBase);
    LogHit("ProcessRequestVtableSlot", processRequestVft, ImageBase);

    FindCurlHttpRequestFields(out, ImageBase, processRequest, processRequestVft, false);

    if (!HasName(out, "SetURLVft"))
    {
        PushIfFound(out, "SetURLVft", 10, true);
        LogHit("SetURLVft", 10, 0, true);
    }

    if (!HasName(out, "GetURLVft"))
    {
        out.push_back({ "GetURLVft", 0, true, false, false });
        printf("  %-40s 0x0\n", "GetURLVft");
    }

    const uint64_t pushWidget = FindPushWidget();
    PushIfFound(out, "PushWidget", pushWidget);
    LogHit("PushWidget", pushWidget, ImageBase);

    const uint64_t requestExit = FindRequestExitWithStatus();
    const uint64_t unsafeEnv = FindUnsafeEnvironmentPopup();

    PushIfFound(out, "RequestExitWithStatus", requestExit);
    PushIfFound(out, "PatchRequestExit", requestExit);
    LogHit("RequestExitWithStatus", requestExit, ImageBase);

    PushIfFound(out, "ShowAppEnvironmentSecurityMessage", unsafeEnv);
    PushIfFound(out, "PatchUnsafeEnvironment", unsafeEnv);
    PushIfFound(out, "UnsafeEnvironmentPopup", unsafeEnv);
    LogHit("UnsafeEnvironmentPopup", unsafeEnv, ImageBase);

    const uint64_t memLeak1 = Precision::Pattern("48 89 5C 24 ?? 57 48 83 EC ?? 48 8B 01 4C 8B C2 48 8D 54 24 ? 48 8B D9 FF 50 30");
    const uint64_t memLeak2 = Precision::Pattern("48 8B 01 4C 8D 41 08 48 FF 60 20");
    const uint64_t memLeak3 = Precision::Pattern("48 89 5C 24 ?? 57 48 83 EC ?? 48 8B 01 4C 8B C2 48 8D 54 24");
    PushIfFound(out, "MemLeakFix1", memLeak1);
    PushIfFound(out, "MemLeakFix2", memLeak2);
    PushIfFound(out, "MemLeakFix3", memLeak3);
    LogHit("MemLeakFix1", memLeak1, ImageBase);
    LogHit("MemLeakFix2", memLeak2, ImageBase);
    LogHit("MemLeakFix3", memLeak3, ImageBase);

    HMODULE eos = GetModuleHandleA("EOSSDK-Win64-Shipping.dll");

    if (eos)
    {
        printf("\n--- EOS ---\n");
        eosBase = uint64_t(eos);
        uint64_t eosProcessRequest = 0;
        uint64_t eosProcessRequestVft = 0;
        FindProcessRequestAndVft(eosBase, true, eosProcessRequest, eosProcessRequestVft);

        PushIfFound(out, "CurlHttpInternalProcessRequestEOS", eosProcessRequest, false, true);
        PushIfFound(out, "ProcessRequestEOS", eosProcessRequest, false, true);
        PushIfFound(out, "EosProcessRequest", eosProcessRequest, false, true);
        PushIfFound(out, "ProcessRequestEOSVft", eosProcessRequestVft, false, true);

        LogHit("ProcessRequestEOS", eosProcessRequest, eosBase, false, true);
        LogHit("EosProcessRequest", eosProcessRequest, eosBase, false, true);
        LogHit("ProcessRequestEOSVft", eosProcessRequestVft, eosBase, false, true);

        FindCurlHttpRequestFields(out, eosBase, eosProcessRequest, eosProcessRequestVft, true);

        PushIfFound(out, "EosSetURLVft", 10, true);
        LogHit("EosSetURLVft", 10, 0, true);
    }
    else
    {
        printf("\n--- EOS (not loaded) ---\n");
        LogHit("EosUrlField", 0, 0, true);
        LogHit("EosProcessRequest", 0);
    }

    printf("--- found %zu redirect offsets ---\n\n", out.size());
    return out;
}
