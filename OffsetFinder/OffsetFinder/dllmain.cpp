#include "pch.h"

#include "Public/Generator.h"

#include <cctype>
#include <iostream>
#include <string>
#include <thread>

static OffsetFinder::Mode PromptMode()
{
    printf("OffsetFinder - What offsets would you like to find, Gameserver or Redirect?\n");
    printf("  [1] Gameserver  (Erbium signatures)\n");
    printf("  [2] Redirect    (Tellurium + Starfall signatures)\n");
    printf("> ");

    std::string Input;
    std::getline(std::cin, Input);

    for (char& C : Input)
        C = (char)std::tolower((unsigned char)C);

    if (Input == "2" || Input == "r" || Input == "redirect")
        return OffsetFinder::Mode::Redirect;

    if (Input == "1" || Input == "g" || Input == "gameserver" || Input.empty())
        return OffsetFinder::Mode::Gameserver;

    printf("Unrecognized option '%s', defaulting to Gameserver.\n", Input.c_str());
    return OffsetFinder::Mode::Gameserver;
}

static void MainThread()
{
    AllocConsole();
    FILE* Stream = nullptr;
    freopen_s(&Stream, "CONOUT$", "w", stdout);
    freopen_s(&Stream, "CONOUT$", "w", stderr);
    freopen_s(&Stream, "CONIN$", "r", stdin);

    SetConsoleTitleW(L"OffsetFinder | Gameserver/ Redirect");

    printf("--------------------------------------------\n");
    printf(" Helix OffsetFinder\n");
    printf(" Gameserver: Erbium (1.7.2 - 30.00)\n");
    printf(" Redirect:   Tellurium + Starfall (1.7.2 - 31.41)\n");
    printf("--------------------------------------------\n\n");

    try
    {
        const auto Mode = PromptMode();
        printf("\n");

        if (Mode == OffsetFinder::Mode::Redirect)
            OffsetFinder::GenerateRedirectOffsets();
        else
            OffsetFinder::GenerateGameserverOffsets();
    }
    catch (const std::exception& Ex)
    {
        printf("[OffsetFinder] Exception: %s\n", Ex.what());
        MessageBoxA(nullptr, Ex.what(), "OffsetFinder", MB_ICONERROR);
    }
    catch (...)
    {
        printf("[OffsetFinder] Unknown exception while generating offsets.\n");
        MessageBoxA(nullptr, "Unknown exception while generating offsets.", "OffsetFinder", MB_ICONERROR);
    }

    printf("\nDone. If you want to generate Gameserver or Redirect offsets again restart your fortnite.\n");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        std::thread(MainThread).detach();
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
