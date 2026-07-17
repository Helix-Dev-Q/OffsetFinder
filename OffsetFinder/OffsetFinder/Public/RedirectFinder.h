#pragma once

#include <cstdint>
#include <vector>

namespace RedirectFinders
{
    struct Result
    {
        const char* Name = nullptr;
        uint64_t Absolute = 0;
        bool IsVft = false;          // vtable index, not an address
        bool RelativeToEOS = false;  // offset off the eos module instead of the game
    };

    // scans tellurium / starfall sigs. only returns hits.
    // eosBase is set if EOSSDK is loaded.
    std::vector<Result> FindAll(uint64_t& eosBase);
}
