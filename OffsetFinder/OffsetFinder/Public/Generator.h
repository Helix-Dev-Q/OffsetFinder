#pragma once
#include <string>

namespace OffsetFinder
{
    enum class Mode
    {
        Gameserver,
        Redirect
    };

    // Erbium signatures (1.7.2 - 30.00) -> Helix-style Offsets.h
    std::string GenerateGameserverOffsets(const std::wstring& OutputPath = L"");

    // Tellurium + Starfall redirect/SSL signatures -> Helix-style Offsets.h
    std::string GenerateRedirectOffsets(const std::wstring& OutputPath = L"");

    // Back-compat alias
    inline std::string GenerateHelixOffsets(const std::wstring& OutputPath = L"")
    {
        return GenerateGameserverOffsets(OutputPath);
    }
}
