#pragma once
#include <string>

namespace OffsetFinder
{
    enum class Mode
    {
        Gameserver,
        Redirect
    };

    std::string GenerateGameserverOffsets(const std::wstring& OutputPath = L"");
    std::string GenerateRedirectOffsets(const std::wstring& OutputPath = L"");

    inline std::string GenerateHelixOffsets(const std::wstring& OutputPath = L"")
    {
        return GenerateGameserverOffsets(OutputPath);
    }
}
