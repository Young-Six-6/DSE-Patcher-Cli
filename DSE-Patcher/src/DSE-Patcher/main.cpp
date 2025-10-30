#include <windows.h>
#include <iostream>
#include <string>
#include <algorithm>
#include <cctype>
#include <cstring>

#include "MyFunctions.h"   // GLOBALS, MyInitVulnerableDrivers, MyThreadProc1, THREAD_TASK_NO
#include "RTCore64.h"
#include "DBUtil.h"

// global instance (defined in MyFunctions.cpp)
extern GLOBALS g;

// keep signature identical to original GUI function so linkage works
int MyDlg1EnableControls(unsigned char ucEnable)
{
    // CLI: just log and return success
    if (ucEnable)
        std::cout << "[CLI] Controls ENABLED\n";
    else
        std::cout << "[CLI] Controls DISABLED\n";
    return 0;
}

// helper: lower-case a std::string
static std::string to_lower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return std::tolower(c); });
    return out;
}

// helper: try to find driver index by name substring (case-insensitive)
// returns -1 if not found
static int find_driver_by_name(const std::string& token)
{
    std::string key = to_lower(token);
    for (unsigned int i = 0; i < MAX_VULNERABLE_DRIVERS; ++i)
    {
        if (g.vd[i].szProvider == NULL) continue;
        std::string prov = to_lower(std::string(g.vd[i].szProvider));
        if (prov.find(key) != std::string::npos) return (int)i;
        // also try service name
        if (g.vd[i].szServiceName) {
            std::string svc = to_lower(std::string(g.vd[i].szServiceName));
            if (svc.find(key) != std::string::npos) return (int)i;
        }
        // also check driver file path if exists
        if (g.vd[i].driverFile[0].szFilePath[0] != 0) {
            std::string path = to_lower(std::string(g.vd[i].driverFile[0].szFilePath));
            if (path.find(key) != std::string::npos) return (int)i;
        }
    }
    return -1;
}

// swap two VULNERABLE_DRIVER entries (simple memswap)
static void swap_vd(VULNERABLE_DRIVER& a, VULNERABLE_DRIVER& b)
{
    VULNERABLE_DRIVER tmp;
    memcpy(&tmp, &a, sizeof(VULNERABLE_DRIVER));
    memcpy(&a, &b, sizeof(VULNERABLE_DRIVER));
    memcpy(&b, &tmp, sizeof(VULNERABLE_DRIVER));
}

static void print_help()
{
    std::cout << "DSE-Patcher CLI\n"
        << "Usage:\n"
        << "  DSE-Patcher.exe --status                  Show DSE status\n"
        << "  DSE-Patcher.exe --disable                 Disable driver signature enforcement\n"
        << "  DSE-Patcher.exe --enable                  Enable driver signature enforcement\n"
        << "  DSE-Patcher.exe --restore                 Restore original DSE value\n"
        << "  DSE-Patcher.exe --driver <index|name>     Choose driver (default: 0 -> RTCore64)\n"
        << "Examples:\n"
        << "  DSE-Patcher.exe --status\n"
        << "  DSE-Patcher.exe --driver 1 --disable\n"
        << "  DSE-Patcher.exe --driver dbutil --disable\n";
}

int main(int argc, char** argv)
{
    if (argc < 2) { print_help(); return 0; }

    // parse args
    std::string cmd;
    int requestedDriverIndex = 0; // default 0 => RTCore64
    bool driverSpecified = false;

    // simple arg parsing: allow args in any order
    for (int i = 1; i < argc; ++i)
    {
        std::string a = argv[i];
        if (a == "--help" || a == "-h") { print_help(); return 0; }
        else if (a == "--status" || a == "--disable" || a == "--enable" || a == "--restore")
        {
            cmd = a;
        }
        else if (a == "--driver")
        {
            if (i + 1 < argc)
            {
                std::string token = argv[++i];
                // check numeric
                bool isnumeric = !token.empty() && std::all_of(token.begin(), token.end(), [](unsigned char c) { return std::isdigit(c); });
                // init globals temporarily for name matching after MyInitVulnerableDrivers
                if (isnumeric) {
                    requestedDriverIndex = atoi(token.c_str());
                    driverSpecified = true;
                }
                else {
                    // we'll match by name after MyInitVulnerableDrivers; store token in requestedDriverIndex as negative marker?
                    // store token into cmd as "drivername::xxxxx" to carry it along; but simpler: save token to a variable
                    // create a small hack: we will reuse 'cmd' only for action, so keep token in a local variable
                    // However to avoid more variables here, let's store token in cmdDriverName (declare)
                }
                // We'll handle name tokens later via separate variable. To simplify, use argv style:
                // Actually let's use a second variable:
                // (We'll break the parsing loop and re-run after initialization)
            }
            else
            {
                std::cerr << "Error: --driver requires an argument\n";
                return 1;
            }
        }
    }

    // re-parse properly to capture driver token name if present
    std::string driverToken;
    for (int i = 1; i < argc; ++i)
    {
        std::string a = argv[i];
        if (a == "--driver" && i + 1 < argc) { driverToken = argv[++i]; break; }
    }

    // prepare globals
    memset(&g, 0, sizeof(GLOBALS));
    g.hInstance = GetModuleHandle(NULL);

    // initialize driver descriptors (populates g.vd[])
    if (MyInitVulnerableDrivers(g.vd, MAX_VULNERABLE_DRIVERS) != 0)
    {
        std::cerr << "Error: MyInitVulnerableDrivers failed\n";
        return 1;
    }

    // determine driver index from token (if provided)
    if (!driverToken.empty())
    {
        // numeric?
        bool isnumeric = !driverToken.empty() && std::all_of(driverToken.begin(), driverToken.end(), [](unsigned char c) { return std::isdigit(c); });
        if (isnumeric)
        {
            int idx = atoi(driverToken.c_str());
            if (idx < 0 || (unsigned)idx >= MAX_VULNERABLE_DRIVERS || g.vd[idx].szProvider == NULL)
            {
                std::cerr << "Error: driver index out of range or not available: " << idx << "\n";
                return 1;
            }
            requestedDriverIndex = idx;
            driverSpecified = true;
        }
        else
        {
            int idx = find_driver_by_name(driverToken);
            if (idx < 0)
            {
                std::cerr << "Error: could not find driver matching '" << driverToken << "'\n";
                return 1;
            }
            requestedDriverIndex = idx;
            driverSpecified = true;
        }
    }

    // ensure requestedDriverIndex valid
    if (requestedDriverIndex < 0 || (unsigned)requestedDriverIndex >= MAX_VULNERABLE_DRIVERS || g.vd[requestedDriverIndex].szProvider == NULL)
    {
        // fallback to 0
        requestedDriverIndex = 0;
    }

    // Move requested driver to index 0 so existing ThreadProc logic (which expects the selected item) picks it.
    if (requestedDriverIndex != 0) {
        swap_vd(g.vd[0], g.vd[requestedDriverIndex]);
    }

    // set dummy HWNDs to avoid early GUI code paths that expect non-null handles
    g.Dlg1.hCombo1 = (HWND)1;
    g.Dlg1.hDialog1 = (HWND)1;
    g.Dlg1.hStatusBar1 = (HWND)1;

    // decide action (if not set earlier, find first action-like arg)
    if (cmd.empty())
    {
        // re-scan args to find action
        for (int i = 1; i < argc; ++i) {
            std::string a = argv[i];
            if (a == "--status" || a == "--disable" || a == "--enable" || a == "--restore") { cmd = a; break; }
        }
    }
    if (cmd.empty()) { print_help(); return 0; }

    // map cmd to thread task
    THREAD_TASK_NO task = ThreadTaskReadDSEOnFirstRun;
    if (cmd == "--status") task = ThreadTaskReadDSEOnFirstRun;
    else if (cmd == "--disable") task = ThreadTaskDisableDSE;
    else if (cmd == "--enable") task = ThreadTaskEnableDSE;
    else if (cmd == "--restore") task = ThreadTaskRestoreDSE;

    // set thread params
    g.ThreadParams.ttno = task;
    g.ucRunning = 1;

    std::cout << "[CLI] Selected driver provider: " << (g.vd[0].szProvider ? g.vd[0].szProvider : "(unknown)") << "\n";

    // call thread proc synchronously (original GUI used CreateThread -> wait)
    DWORD rc = (DWORD)MyThreadProc1((PVOID)&g.ThreadParams);

    // After operation add a safety wait for actions that change kernel state
    if (task == ThreadTaskDisableDSE || task == ThreadTaskEnableDSE || task == ThreadTaskRestoreDSE)
    {
        const DWORD SAFETY_WAIT_MS = 1000; // 1 second
        std::cout << "[CLI] Waiting " << SAFETY_WAIT_MS << " ms to allow kernel state to stabilize...\n";
        Sleep(SAFETY_WAIT_MS);
    }

    // determine success (basic heuristic: rc == 0 or g.pd.dwDSEActualValue set)
    bool success = (rc == 0);
    // if patch data present, consider actual value meaningful
    if (g.pd.dwDSEActualValue != 0 || g.pd.dwDSEOriginalValue != 0)
    {
        // treat success if return code == 0 OR we can read a real value
        success = success || true; // still print details below
    }

    // print result summary
    std::cout << "[CLI] Operation finished. Return code: " << rc << (success ? " (success)\n" : " (may indicate failure)\n");

    // printed chosen driver provider already; print module name if available
    if (g.pd.szModuleName && strlen(g.pd.szModuleName) > 0) {
        std::cout << "[CLI] Target module: " << g.pd.szModuleName << "\n";
    }
    else {
        std::cout << "[CLI] Target module: (unknown)\n";
    }

    // more DSE related info if available
    std::cout << "[CLI] DSE actual value:   " << g.pd.dwDSEActualValue << "\n";
    std::cout << "[CLI] DSE original value: " << g.pd.dwDSEOriginalValue << "\n";
    std::cout << "[CLI] DSE disable value:  " << g.pd.dwDSEDisableValue << "\n";
    std::cout << "[CLI] DSE enable value:   " << g.pd.dwDSEEnableValue << "\n";

    // also print which driver file was used (if present)
    if (g.vd[0].driverFile[0].szFilePath[0] != 0) {
        std::cout << "[CLI] Driver file used: " << g.vd[0].driverFile[0].szFilePath << "\n";
    }
    else {
        std::cout << "[CLI] Driver file used: (embedded/unknown)\n";
    }

    return (int)rc;
}
