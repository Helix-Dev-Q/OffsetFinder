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

    // find a pointer to `func` outside .text (vtable lives in rdata/data)
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

                if (CheckBytesUp(sref, i, { 0x48, 0x89, 0x5C }))
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

    // collect every rip-relative lea in .text that points at `target`
    void CollectLeaRefsTo(uint64_t moduleBase, uint64_t target, std::vector<uint64_t>& out)
    {
        auto text = GetSection(moduleBase, ".text");
        if (!text || !target)
            return;

        auto start = (uint8_t*)(moduleBase + text->VirtualAddress);
        const uint32_t size = text->Misc.VirtualSize;

        for (uint32_t i = 0; i + 7 < size; i++)
        {
            // 48/4C 8D ?? xx xx xx xx  (RIP-relative when modrm is 0x0D/0x15/0x1D/0x25/0x2D/0x35/0x3D)
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

        // fallback: whole image
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

    // pick the ProcessRequest that actually has a vtable pointer (first string hit is often wrong)
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

        // also try memcury first-hit as an extra candidate source
        {
            auto saved = ImageBase;
            ImageBase = moduleBase;
            if (auto sref = Memcury::Scanner::FindStringRef(L"STAT_FCurlHttpRequest_ProcessRequest", false).Get())
            {
                if (auto fn = ResolveProcessRequestStart(sref, bEos))
                {
                    if (auto slot = FindVftSlotForFunc(moduleBase, fn))
                    {
                        outFunc = fn;
                        outVftSlot = slot;
                        ImageBase = saved;
                        return true;
                    }
                    if (!outFunc)
                        outFunc = fn;
                }
            }
            ImageBase = saved;
        }

        std::vector<uint64_t> leaRefs;
        for (auto strAddr : stringAddrs)
            CollectLeaRefsTo(moduleBase, strAddr, leaRefs);

        printf("  ProcessRequest candidates: %zu string-ref(s)\n", leaRefs.size());

        for (auto sref : leaRefs)
        {
            const uint64_t fn = ResolveProcessRequestStart(sref, bEos);
            if (!fn)
                continue;

            const uint64_t slot = FindVftSlotForFunc(moduleBase, fn);
            if (slot)
            {
                outFunc = fn;
                outVftSlot = slot;
                return true;
            }

            if (!outFunc)
                outFunc = fn;
        }

        // last resort: whatever we have + scan for vft anyway
        if (outFunc)
            outVftSlot = FindVftSlotForFunc(moduleBase, outFunc);

        return outFunc != 0;
    }

    // pull a rcx-relative displ from common lea/mov encodings
    bool TryReadRcxDisp(uint8_t* p, uint32_t& outOff)
    {
        // lea/mov r64, [rcx+imm32]  : 48/4C 8D/8B 8x/9x/81/91/... with ModRM mod=2, rm=1 (rcx)
        // ModRM: xx xxx 001 for rcx, mod = 10 (disp32) => mask check on low 3 bits == 1 and (modrm >> 6) == 2
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

        // add rcx, imm32
        if (p[0] == 0x48 && p[1] == 0x81 && p[2] == 0xC1)
        {
            outOff = *(uint32_t*)(p + 3);
            return true;
        }

        // lea rdx, [rcx+imm32] exact starfall
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

    // scan vtable slots around ProcessRequest for a GetURL-like func that exposes UrlField
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

        // walk back from ProcessRequest; keep the furthest-back func that exposes a UrlField
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

        // walk bestBase further back for true vtable start
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

                // prefer add rcx, UrlField (SetURL usually bumps this then assigns)
                if (CheckBytesAt(func, j, { 0x48, 0x81, 0xC1 }) || CheckBytesAt(func, j, { 0x48, 0x8D, 0x89 }))
                {
                    if (outIdx)
                        *outIdx = i;
                    return func;
                }
            }
        }

        // looser: any vtable func that touches UrlField
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

    // brute .text for add rcx, UrlField / lea rcx, [rcx+UrlField]
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

            // walk up a bit for a typical prologue
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

            // mov dword ptr [rcx+imm32], 0
            if (p[0] == 0xC7 && p[1] == 0x81 && *(uint32_t*)(p + 6) == 0)
            {
                const uint32_t off = *(uint32_t*)(p + 2);
                if (LooksLikeBlockFlag(off, urlField))
                    return off;
            }

            // mov byte ptr [rcx+imm32], 0
            if (p[0] == 0xC6 && p[1] == 0x81 && p[6] == 0)
            {
                const uint32_t off = *(uint32_t*)(p + 2);
                if (LooksLikeBlockFlag(off, urlField))
                    return off;
            }

            // cmp dword ptr [rcx+imm32], 0
            if (p[0] == 0x83 && p[1] == 0xB9 && p[6] == 0)
            {
                const uint32_t off = *(uint32_t*)(p + 2);
                if (LooksLikeBlockFlag(off, urlField))
                    return off;
            }

            // cmp byte ptr [rcx+imm32], 0
            if (p[0] == 0x80 && p[1] == 0xB9 && p[6] == 0)
            {
                const uint32_t off = *(uint32_t*)(p + 2);
                if (LooksLikeBlockFlag(off, urlField))
                    return off;
            }

            // test byte/dword [rcx+imm32]
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

            // imm8 forms
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

    void PushIfFound(std::vector<RedirectFinders::Result>& out, const char* name, uint64_t absolute,
        bool isVft = false, bool relativeToEos = false, bool isMemberOffset = false)
    {
        if (!absolute)
            return;

        out.push_back({ name, absolute, isVft, relativeToEos, isMemberOffset });
    }

    void FindCurlHttpRequestFields(std::vector<RedirectFinders::Result>& out, uint64_t moduleBase,
        uint64_t processRequest, uint64_t processRequestSlot, bool bEos)
    {
        const char* urlName = bEos ? "EosUrlField" : "UrlField";

        printf("  resolving %s...\n", urlName);

        uint64_t getUrl = 0;
        uint64_t vtable = 0;
        uint32_t urlField = FindUrlFieldFromVtable(moduleBase, processRequestSlot, &getUrl, &vtable);

        if (!urlField && processRequest)
        {
            printf("  %s: vtable miss, scanning ProcessRequest\n", urlName);
            urlField = FindUrlFieldInFunc(processRequest, 0xC00);
        }

        if (urlField)
        {
            printf("  %-40s 0x%X\n", urlName, urlField);
            PushIfFound(out, urlName, urlField, false, false, true);
        }
        else
        {
            printf("  %-40s NOT FOUND\n", urlName);
        }

        if (bEos)
            return;

        printf("  resolving SetURL / UrlSetBlockFlag...\n");

        int64_t setUrlIdx = 0;
        uint64_t setUrl = FindSetURLInVtable(vtable, urlField, processRequestSlot, &setUrlIdx);
        if (!setUrl)
            setUrl = FindSetURLInText(moduleBase, urlField);

        if (setUrl)
        {
            printf("  %-40s 0x%llX\n", "SetURL", setUrl - moduleBase);
            PushIfFound(out, "SetURL", setUrl);
            if (setUrlIdx)
                PushIfFound(out, "SetURLVft", uint64_t(setUrlIdx), true);
        }
        else
        {
            printf("  %-40s NOT FOUND\n", "SetURL");
        }

        const uint32_t blockFlag = FindUrlSetBlockFlag(setUrl, urlField);
        if (blockFlag)
        {
            printf("  %-40s 0x%X\n", "UrlSetBlockFlag", blockFlag);
            PushIfFound(out, "UrlSetBlockFlag", blockFlag, false, false, true);
        }
        else
        {
            printf("  %-40s NOT FOUND\n", "UrlSetBlockFlag");
        }
    }
}

std::vector<RedirectFinders::Result> RedirectFinders::FindAll(uint64_t& eosBase)
{
    std::vector<Result> out;
    eosBase = 0;

    PushIfFound(out, "Realloc", Memcury::Scanner::FindPattern("48 89 5C 24 08 48 89 74 24 10 57 48 83 EC ? 48 8B F1 41 8B D8 48 8B 0D ? ? ? ?").Get());

    uint64_t processRequest = 0;
    uint64_t processRequestVft = 0;
    FindProcessRequestAndVft(ImageBase, false, processRequest, processRequestVft);

    PushIfFound(out, "CurlHttpInternalProcessRequest", processRequest);
    PushIfFound(out, "ProcessRequest", processRequest);
    PushIfFound(out, "ProcessRequestVft", processRequestVft);

    printf("  ProcessRequest                       %s (0x%llX)\n", processRequest ? "ok" : "miss",
        processRequest ? processRequest - ImageBase : 0ull);
    printf("  ProcessRequestVft                    %s (0x%llX)\n", processRequestVft ? "ok" : "miss",
        processRequestVft ? processRequestVft - ImageBase : 0ull);

    FindCurlHttpRequestFields(out, ImageBase, processRequest, processRequestVft, false);

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

    PushIfFound(out, "MemLeakFix1", Memcury::Scanner::FindPattern("48 8B 01 4C 8D 41 08 48 FF 60 20").Get());
    PushIfFound(out, "MemLeakFix2", Memcury::Scanner::FindPattern("48 89 5C 24 ?? 57 48 83 EC ?? 48 8B 01 4C 8B C2 48 8D 54 24").Get());

    bool hasSetUrlVft = false;
    for (auto& e : out)
    {
        if (e.Name && strcmp(e.Name, "SetURLVft") == 0)
        {
            hasSetUrlVft = true;
            break;
        }
    }
    if (!hasSetUrlVft)
        PushIfFound(out, "SetURLVft", 10, true, false);

    HMODULE eos = GetModuleHandleA("EOSSDK-Win64-Shipping.dll");
    if (!eos)
        eos = LoadLibraryA("EOSSDK-Win64-Shipping.dll");

    if (eos)
    {
        eosBase = uint64_t(eos);
        uint64_t eosProcessRequest = 0;
        uint64_t eosProcessRequestVft = 0;
        FindProcessRequestAndVft(eosBase, true, eosProcessRequest, eosProcessRequestVft);

        PushIfFound(out, "CurlHttpInternalProcessRequestEOS", eosProcessRequest, false, true);
        PushIfFound(out, "ProcessRequestEOS", eosProcessRequest, false, true);
        PushIfFound(out, "ProcessRequestEOSVft", eosProcessRequestVft, false, true);

        printf("  ProcessRequestEOS                    %s (EOS+0x%llX)\n", eosProcessRequest ? "ok" : "miss",
            eosProcessRequest ? eosProcessRequest - eosBase : 0ull);
        printf("  ProcessRequestEOSVft                 %s (EOS+0x%llX)\n", eosProcessRequestVft ? "ok" : "miss",
            eosProcessRequestVft ? eosProcessRequestVft - eosBase : 0ull);

        FindCurlHttpRequestFields(out, eosBase, eosProcessRequest, eosProcessRequestVft, true);
    }
    else
    {
        printf("  EosUrlField                              NOT FOUND (no EOSSDK)\n");
    }

    return out;
}
