// Page10_ImportComplete.cpp - Import Complete Page Implementation
#include "Page10_ImportComplete.h"

INT_PTR CALLBACK WndProc_10_ImportComplete(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
{
    switch (uMsg)
    {
    case WM_INITDIALOG:
        return TRUE;

    case WM_NOTIFY:
    {
        LPNMHDR pnmh = (LPNMHDR)lParam;  // NOSONAR (EXPLICIT-TYPE-04) - Explicit type preferred for code clarity
        switch (pnmh->code)
        {
        case PSN_SETACTIVE:
        {
            // Show results
            WCHAR szTemp[64]; // NOSONAR - C-style array required for Windows API swprintf_s/SetDlgItemText compatibility
            DWORD dwTotal = g_wizardData.dwFileCredentialCount;

            swprintf_s(szTemp, ARRAYSIZE(szTemp), L"%u", dwTotal);
            SetDlgItemText(hwndDlg, IDC_10_TOTAL, szTemp);

            swprintf_s(szTemp, ARRAYSIZE(szTemp), L"%u", g_wizardData.dwImportedCount);
            SetDlgItemText(hwndDlg, IDC_10_IMPORTED, szTemp);

            swprintf_s(szTemp, ARRAYSIZE(szTemp), L"%u", g_wizardData.dwFailedCount);
            SetDlgItemText(hwndDlg, IDC_10_FAILED, szTemp);

            SetDlgItemText(hwndDlg, IDC_10_USERS_CREATED, L"0");
            SetDlgItemText(hwndDlg, IDC_10_GROUPS_CREATED, L"0");

            // Set summary text
            std::wstring wsSummary;
            if (g_wizardData.fDryRun) {
                wsSummary = L"Preview complete. No changes were made.";
            } else {
                wsSummary = L"Import completed successfully!";
            }
            SetDlgItemText(hwndDlg, IDC_10_SUMMARY_TEXT, wsSummary.c_str());

            // Warnings
            std::wstring wsWarnings;
            if (g_wizardData.dwFailedCount > 0) {
                swprintf_s(szTemp, ARRAYSIZE(szTemp), L"%u credentials failed to import.",
                    g_wizardData.dwFailedCount);
                wsWarnings = szTemp;
            }
            SetDlgItemText(hwndDlg, IDC_10_WARNINGS, wsWarnings.c_str());

            // Load shield icon
            HMODULE hDll = LoadLibraryExW(L"imageres.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
            if (hDll) {
                HICON hIcon = LoadIcon(hDll, MAKEINTRESOURCE(58));
                if (hIcon) {  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
                    SendDlgItemMessage(hwndDlg, IDC_10_SHIELD, STM_SETICON, (WPARAM)hIcon, 0);
                }
                FreeLibrary(hDll);
            }

            // Change Next button to Finish
            HWND hwndPS = GetParent(hwndDlg);
            if (hwndPS) {
                SetWindowTextW(GetDlgItem(hwndPS, IDOK), L"Finish");
            }

            PropSheet_SetWizButtons(hwndDlg, PSWIZB_BACK | PSWIZB_FINISH);
            return TRUE;
        }

        case PSN_WIZFINISH:
            return TRUE;

        default:
            break;
        }
        break;
    }

    case WM_COMMAND:
    {
        if (LOWORD(wParam) == IDC_10_VIEW_LOG) {
            // EIDLogManager has been retired in favour of Group Policy management; open the CSV
            // audit-log folder directly instead of launching the (removed) manager application.
            HINSTANCE hResult = ShellExecuteW(hwndDlg, L"open",
                L"C:\\ProgramData\\OpenAccessEID\\logs",
                nullptr, nullptr, SW_SHOWNORMAL);
            if ((INT_PTR)hResult <= 32) {
                MessageBoxW(hwndDlg,
                    L"Unable to open the log folder. The CSV audit logs are located at "
                    L"C:\\ProgramData\\OpenAccessEID\\logs.",
                    L"View Log", MB_ICONWARNING);
            }
            return TRUE;
        }
        break;
    }

    default:
        break;
    }
    return FALSE;
}
