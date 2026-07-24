#pragma once

#include "pch.h"

#include <algorithm>
#include <utility>
#include <vector>

namespace Precision
{
    inline IMAGE_SECTION_HEADER* GetSection(const char* Name)
    {
        if (!ImageBase || !Name)
            return nullptr;

        auto Dos = (IMAGE_DOS_HEADER*)ImageBase;
        if (Dos->e_magic != IMAGE_DOS_SIGNATURE)
            return nullptr;

        auto Nt = (IMAGE_NT_HEADERS*)(ImageBase + Dos->e_lfanew);
        if (Nt->Signature != IMAGE_NT_SIGNATURE)
            return nullptr;

        auto Section = IMAGE_FIRST_SECTION(Nt);
        for (int i = 0; i < Nt->FileHeader.NumberOfSections; i++, Section++)
        {
            if (strncmp((const char*)Section->Name, Name, 8) == 0)
                return Section;
        }
        return nullptr;
    }

    inline bool InSection(uint64_t Addr, const char* Name)
    {
        auto Sec = GetSection(Name);
        if (!Sec || !Addr)
            return false;
        const uint64_t Start = ImageBase + Sec->VirtualAddress;
        return Addr >= Start && Addr < Start + Sec->Misc.VirtualSize;
    }

    inline bool InText(uint64_t Addr)
    {
        return InSection(Addr, ".text");
    }

    inline bool InTextRange(uint64_t Addr, size_t Bytes)
    {
        return Bytes && InText(Addr) && InText(Addr + Bytes - 1);
    }

    inline bool IsPrologue(const uint8_t* P)
    {
        if (!P || !InTextRange(uint64_t(P), 4))
            return false;

        if (P[0] == 0x48 && P[1] == 0x89 && P[2] == 0x5C)
            return true;
        if (P[0] == 0x48 && P[1] == 0x8B && P[2] == 0xC4)
            return true;
        if (P[0] == 0x4C && P[1] == 0x8B && P[2] == 0xDC)
            return true;
        if (P[0] == 0x40 && (P[1] == 0x53 || P[1] == 0x55 || P[1] == 0x56 || P[1] == 0x57))
            return true;
        if (P[0] == 0x41 && P[1] == 0x56 && P[2] == 0x41 && P[3] == 0x57)
            return true;
        if (P[0] == 0x41 && P[1] == 0x56 && P[2] == 0x48)
            return true;
        if (P[0] == 0x48 && P[1] == 0x83 && P[2] == 0xEC)
            return true;
        if (P[0] == 0x48 && P[1] == 0x81 && P[2] == 0xEC)
            return true;
        if (P[0] == 0x55 && P[1] == 0x48 && P[2] == 0x8B && P[3] == 0xEC)
            return true;
        return false;
    }

    inline bool LooksLikeFuncBoundaryByte(uint8_t B)
    {
        return B == 0xCC || B == 0xC3 || B == 0x90 || B == 0x00;
    }

    inline uint64_t ResolveFuncStart(uint64_t Hit, int MaxBack = 0x400)
    {
        if (!Hit || !InText(Hit))
            return 0;

        uint64_t Best = 0;
        for (int i = 0; i < MaxBack; i++)
        {
            auto P = (uint8_t*)(Hit - i);
            if (!InText(uint64_t(P)))
                break;

            if (!IsPrologue(P))
                continue;

            const bool Padded = i > 0 && InText(uint64_t(P) - 1) && LooksLikeFuncBoundaryByte(*(P - 1));
            if (Padded)
                return uint64_t(P);

            if (!Best)
                Best = uint64_t(P);
        }

        if (!Best)
        {
            auto Bound = Memcury::Scanner(Hit).FindFunctionBoundary(false).Get();
            if (Bound && InText(Bound))
            {
                for (int i = 0; i < 0x40; i++)
                {
                    auto P = (uint8_t*)(Bound + i);
                    if (IsPrologue(P) && uint64_t(P) <= Hit)
                        return uint64_t(P);
                }
                if (IsPrologue((uint8_t*)Bound))
                    return Bound;
            }
        }

        return Best;
    }

    inline bool FuncContains(uint64_t Func, uint64_t Needle, int Window = 0x600)
    {
        return Func && Needle >= Func && Needle < Func + Window;
    }

    inline bool FuncContainsPattern(uint64_t Func, const char* Signature, int Window = 0x600)
    {
        if (!Func || !Signature || !InText(Func))
            return false;

        auto Bytes = Memcury::ASM::pattern2bytes(Signature);
        if (Bytes.empty())
            return false;

        auto Start = (uint8_t*)Func;
        const size_t S = Bytes.size();
        for (int i = 0; i + (int)S <= Window; i++)
        {
            if (!InTextRange(Func + i, S))
                break;

            bool Ok = true;
            for (size_t j = 0; j < S; j++)
            {
                if (Bytes[j] != -1 && Start[i + j] != (uint8_t)Bytes[j])
                {
                    Ok = false;
                    break;
                }
            }
            if (Ok)
                return true;
        }
        return false;
    }

    inline std::vector<uint64_t> FindAllPatterns(const char* Signature, int MaxHits = 12)
    {
        std::vector<uint64_t> Out;
        if (!Signature || MaxHits <= 0)
            return Out;

        auto Sec = GetSection(".text");
        if (!Sec)
            return Out;

        auto Bytes = Memcury::ASM::pattern2bytes(Signature);
        if (Bytes.empty())
            return Out;

        auto Start = (uint8_t*)(ImageBase + Sec->VirtualAddress);
        const uint32_t Size = Sec->Misc.VirtualSize;
        const size_t S = Bytes.size();
        if (!S || Size <= S)
            return Out;

        for (uint32_t i = 0; i + S < Size && (int)Out.size() < MaxHits; i++)
        {
            bool Ok = true;
            for (size_t j = 0; j < S; j++)
            {
                if (Bytes[j] != -1 && Start[i + j] != (uint8_t)Bytes[j])
                {
                    Ok = false;
                    break;
                }
            }
            if (!Ok)
                continue;
            Out.push_back(uint64_t(Start + i));
        }
        return Out;
    }

    inline int CountCallXrefs(uint64_t Func, int MaxScanHits = 8)
    {
        if (!Func || !InText(Func))
            return 0;

        auto Sec = GetSection(".text");
        if (!Sec)
            return 0;

        auto Start = (uint8_t*)(ImageBase + Sec->VirtualAddress);
        const uint32_t Size = Sec->Misc.VirtualSize;
        const uint32_t MaxScan = (std::min)(Size, (uint32_t)0x200000); // 2MB
        int Count = 0;

        for (uint32_t i = 0; i + 5 < MaxScan; i++)
        {
            if (Start[i] != 0xE8)
                continue;

            const int32_t Rel = *(int32_t*)(Start + i + 1);
            const uint64_t Target = uint64_t(Start + i + 5) + Rel;
            if (Target == Func)
            {
                Count++;
                if (Count >= MaxScanHits)
                    break;
            }
        }
        return Count;
    }

    inline bool FuncInVft(uint64_t Func, const char* ClassName, int MaxSlots = 0x120)
    {
        if (!Func || !ClassName)
            return false;

        auto Obj = DefaultObjImpl(ClassName);
        if (!Obj || !Obj->Vft)
            return false;

        for (int i = 0; i < MaxSlots; i++)
        {
            if (uint64_t(Obj->Vft[i]) == Func)
                return true;
        }
        return false;
    }

    template <typename F>
    inline uint64_t PickBest(const std::vector<uint64_t>& Hits, F&& ScoreExtra)
    {
        uint64_t Best = 0;
        int BestScore = -1;

        for (auto Hit : Hits)
        {
            const uint64_t Func = ResolveFuncStart(Hit);
            if (!Func || !InText(Func) || !FuncContains(Func, Hit))
                continue;

            int Score = 1;
            auto P = (uint8_t*)Func;
            if (InText(Func - 1) && LooksLikeFuncBoundaryByte(*(P - 1)))
                Score += 5;

            Score += ScoreExtra(Func, Hit);

            if (Score > BestScore)
            {
                BestScore = Score;
                Best = Func;
            }
        }

        return Best;
    }

    inline uint64_t PickBest(const std::vector<uint64_t>& Hits)
    {
        return PickBest(Hits, [](uint64_t, uint64_t) { return 0; });
    }

    template <typename F>
    inline uint64_t FindBestPattern(std::initializer_list<const char*> Signatures, F&& ScoreExtra)
    {
        std::vector<uint64_t> All;
        for (auto Sig : Signatures)
        {
            auto Hits = FindAllPatterns(Sig);
            All.insert(All.end(), Hits.begin(), Hits.end());
        }
        return PickBest(All, std::forward<F>(ScoreExtra));
    }

    inline uint64_t FindBestPattern(std::initializer_list<const char*> Signatures)
    {
        return FindBestPattern(Signatures, [](uint64_t, uint64_t) { return 0; });
    }

    inline uint64_t WalkBackToPrologueFromString(uint64_t SRef, int MaxBack = 0x800)
    {
        if (!SRef)
            return 0;

        if (MaxBack > 0x2000)
            MaxBack = 0x2000;

        uint64_t Best = 0;
        for (int i = 0; i < MaxBack; i++)
        {
            auto P = (uint8_t*)(SRef - i);
            if (!InText(uint64_t(P)))
                break;
            if (!IsPrologue(P))
                continue;

            if (i > 0 && InText(uint64_t(P) - 1) && LooksLikeFuncBoundaryByte(*(P - 1)))
                return uint64_t(P);
            if (!Best)
                Best = uint64_t(P);
        }
        return Best;
    }

    inline bool PreferInFuncStringRefs()
    {
        return VersionInfo.FortniteVersion >= 19.00 || VersionInfo.EngineVersion >= 5.0;
    }

    inline bool UseUE51StringRefs()
    {
        return PreferInFuncStringRefs();
    }

    inline uint64_t FindStringRefSmart(const wchar_t* Str, int UseRefNum = 0)
    {
        if (!Str)
            return 0;

        const bool Prefer = PreferInFuncStringRefs();
        auto A = Memcury::Scanner::FindStringRef(Str, false, UseRefNum, Prefer).Get();
        if (A)
            return A;
        return Memcury::Scanner::FindStringRef(Str, false, UseRefNum, !Prefer).Get();
    }

    inline uint64_t FromString(const wchar_t* Str, int MaxBack = 0x800)
    {
        return WalkBackToPrologueFromString(FindStringRefSmart(Str), MaxBack);
    }

    inline uint64_t Pattern(const char* Sig)
    {
        if (!Sig)
            return 0;

        auto First = Memcury::Scanner::FindPattern(Sig).Get();
        if (First && InText(First))
        {
            if (auto Resolved = ResolveFuncStart(First))
                return Resolved;
            if (IsPrologue((uint8_t*)First))
                return First;
        }

        auto Hits = FindAllPatterns(Sig, 8);
        if (Hits.empty())
            return First && InText(First) ? First : 0;
        if (auto Best = PickBest(Hits))
            return Best;
        return ResolveFuncStart(Hits[0]);
    }

    inline uint64_t Patterns(std::initializer_list<const char*> Sigs)
    {
        for (auto Sig : Sigs)
        {
            if (auto Hit = Pattern(Sig))
                return Hit;
        }
        return 0;
    }

    inline bool IsReadableDataPtr(uint64_t Addr)
    {
        if (!Addr || Addr < ImageBase)
            return false;
        if (InText(Addr))
            return false;
        return InSection(Addr, ".data") || InSection(Addr, ".rdata") || InSection(Addr, ".bss")
            || (Addr > ImageBase && Addr < ImageBase + 0x10000000);
    }
}
