// main.cpp - CLI wrapper for DSE-Patcher (minimal changes)
#include <windows.h>
#include <iostream>
#include <string>
#include <cstring>

// include project headers
#include "MyFunctions.h"   // contains THREAD_TASK_NO, MyInitVulnerableDrivers, MyThreadProc1, GLOBALS typedef
#include "RTCore64.h"
#include "DBUtil.h"

// declare global instance defined in MyFunctions.cpp
extern GLOBALS g;

// stub for GUI enable/disable function (signature must match original)
int MyDlg1EnableControls(unsigned char ucEnable)
{
    // CLI mode: just print a short message and return success
    if (ucEnable)
        std::cout << "[CLI] Controls ENABLED\n";
    else
        std::cout << "[CLI] Controls DISABLED\n";
    return 0;
}

static void print_help()
{
    std::cout << "DSE-Patcher CLI\n"
        << "Usage:\n"
        << "  DSE-Patcher.exe --status    Show DSE status\n"
        << "  DSE-Patcher.exe --disable   Disable driver signature enforcement\n"
        << "  DSE-Patcher.exe --enable    Enable driver signature enforcement\n"
        << "  DSE-Patcher.exe --restore   Restore original DSE value\n"
        << "  DSE-Patcher.exe --help      Show this help\n";
}

int main(int argc, char** argv)
{
    if (argc < 2) { print_help(); return 0; }

    std::string cmd = argv[1];

    // set debug privilege (original GUI called EnableDebugPrivilege in MyDialog1.cpp)
    // we don't reimplement EnableDebugPrivilege here; you can keep it in MyDialog1.cpp or call it if available.
    // But MyFunctions contains MySetPrivilege etc. If you want call EnableDebugPrivilege, add extern and call.

    // zero globals (like GUI OnInitDialog does)
    memset(&g, 0, sizeof(GLOBALS));
    g.hInstance = GetModuleHandle(NULL);

    // initialize vulnerable drivers (same as GUI OnInitDialog)
    if (MyInitVulnerableDrivers(g.vd, MAX_VULNERABLE_DRIVERS) != 0)
    {
        std::cerr << "Error: MyInitVulnerableDrivers failed\n";
        return 1;
    }

    // Make the code paths in MyThreadProc1 treat a "first item selected" and existing statusbar:
    // Many parts use SendMessage(hCombo1, CB_GETCURSEL, ...) and SendMessage(statusbar,...).
    // If these HWND's are NULL their use might trigger error branches. Set to non-NULL dummy values:
    g.Dlg1.hCombo1 = (HWND)1;
    g.Dlg1.hStatusBar1 = (HWND)1;
    g.Dlg1.hDialog1 = (HWND)1;
    // also ensure timer counters zeroed (MyThreadProc1 sets them anyway)
    g.Dlg1.uiTimerHours = g.Dlg1.uiTimerMinutes = g.Dlg1.uiTimerSeconds = 0;

    // set thread task based on command
    if (cmd == "--status")
    {
        std::cout << "Checking DSE status...\n";
        g.ThreadParams.ttno = ThreadTaskReadDSEOnFirstRun;
    }
    else if (cmd == "--disable")
    {
        std::cout << "Disabling DSE...\n";
        g.ThreadParams.ttno = ThreadTaskDisableDSE;
    }
    else if (cmd == "--enable")
    {
        std::cout << "Enabling DSE...\n";
        g.ThreadParams.ttno = ThreadTaskEnableDSE;
    }
    else if (cmd == "--restore")
    {
        std::cout << "Restoring DSE...\n";
        g.ThreadParams.ttno = ThreadTaskRestoreDSE;
    }
    else if (cmd == "--help")
    {
        print_help();
        return 0;
    }
    else
    {
        std::cerr << "Unknown command: " << cmd << "\n";
        print_help();
        return 1;
    }

    // mark running and call the thread proc synchronously
    g.ucRunning = 1;

    DWORD rc = 0;
    // MyThreadProc1 expects a pointer to THREAD_PARAMS; original GUI created a thread
    // but we'll call it synchronously to wait for completion.
    rc = (DWORD)MyThreadProc1((PVOID)&g.ThreadParams);

    // After completion, try to print DSE status (PATCH_DATA inside g)
    std::cout << "Operation finished. Thread return code: " << rc << "\n";

    // g.pd is a PATCH_DATA struct (in GLOBALS), try to print readable info if present
    // careful: szDSEStatus might be NULL in some code paths, but its declared as const char* inside PATCH_DATA.
    if (g.pd.szDSEStatus != NULL && strlen(g.pd.szDSEStatus) > 0)
    {
        std::cout << "DSE status text : " << g.pd.szDSEStatus << "\n";
    }
    std::cout << "DSE actual value: " << g.pd.dwDSEActualValue << "\n";
    std::cout << "DSE original val: " << g.pd.dwDSEOriginalValue << "\n";
    std::cout << "DSE disable  val: " << g.pd.dwDSEDisableValue << "\n";
    std::cout << "DSE enable   val: " << g.pd.dwDSEEnableValue << "\n";

    return (int)rc;
}
