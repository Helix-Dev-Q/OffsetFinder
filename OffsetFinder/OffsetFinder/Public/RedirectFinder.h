#pragma once

#include <cstdint>
#include <vector>

namespace RedirectFinders
{
    struct Result
    {
        const char* Name = nullptr;
        uint64_t Absolute = 0;
        bool IsVft = false;
        bool RelativeToEOS = false;
        bool IsMemberOffset = false;
    };

    std::vector<Result> FindAll(uint64_t& eosBase);
}
