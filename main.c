//#define UNICODE
#define _UNICODE
#include <windows.h>
#include <richedit.h>
#include <stdio.h>
#include "core.h"

#pragma comment(lib, "Comctl32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Gdi32.lib")
#pragma comment(lib, "Advapi32.lib")

HWND hPasswordEdit, hUnlockButton;
HWND hEdit, hSaveButton, hLogoutButton;
HFONT hFont;
BOOL isUnlocked = FALSE;

LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void ShowLoginUI(HWND hwnd);
void ShowEditorUI(HWND hwnd);
void DestroyLoginUI(void);
void DestroyEditorUI(void);
void LoadAndDecryptText(HWND hEdit);
void SaveEncryptedText(HWND hEdit);

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
    LoadLibrary(TEXT("Msftedit.dll"));

    const wchar_t CLASS_NAME[] = L"SecureNotesWindow";

    WNDCLASS wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_SHIELD);

    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(
        0, CLASS_NAME, L"Secure Notes",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 700, 500,
        NULL, NULL, hInstance, NULL);

    if (!hwnd)
        return 0;

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        LOGFONT lf = {0};
        lf.lfHeight = -18;
        wcscpy_s(lf.lfFaceName, LF_FACESIZE, L"Segoe UI");
        hFont = CreateFontIndirect(&lf);

        ShowLoginUI(hwnd);
        return 0;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == 1001) // Unlock
        {
            wchar_t pwbuf[256];
            GetWindowTextW(hPasswordEdit, pwbuf, 256);

            char password[256];
            WideCharToMultiByte(CP_UTF8, 0, pwbuf, -1, password, 256, NULL, NULL);

            if (DeriveAESKeyFromPassword(password))
            {
                isUnlocked = TRUE;
                DestroyLoginUI();
                ShowEditorUI(hwnd);
                LoadAndDecryptText(hEdit);
            }
            else
            {
                MessageBox(hwnd, L"Failed to derive AES key.", L"Error", MB_ICONERROR);
            }
            return 0;
        }
        else if (LOWORD(wParam) == 1002) // Save
        {
            SaveEncryptedText(hEdit);
            MessageBox(hwnd, L"Note encrypted and saved.", L"Success", MB_ICONINFORMATION);
            return 0;
        }
        else if (LOWORD(wParam) == 1003) // Logout
        {
            DestroyEditorUI();
            isUnlocked = FALSE;
            ShowLoginUI(hwnd);
            return 0;
        }
        break;

    case WM_SIZE:
        if (isUnlocked)
        {
            RECT rc;
            GetClientRect(hwnd, &rc);
            MoveWindow(hEdit, 10, 10, rc.right - 20, rc.bottom - 60, TRUE);
            MoveWindow(hSaveButton, rc.right - 160, rc.bottom - 40, 140, 28, TRUE);
            MoveWindow(hLogoutButton, 10, rc.bottom - 40, 100, 28, TRUE);
        }
        else
        {
            RECT rc;
            GetClientRect(hwnd, &rc);
            MoveWindow(hPasswordEdit, rc.right / 2 - 150, rc.bottom / 2 - 20, 300, 24, TRUE);
            MoveWindow(hUnlockButton, rc.right / 2 - 60, rc.bottom / 2 + 20, 120, 28, TRUE);
        }
        return 0;

    case WM_DESTROY:
        DeleteObject(hFont);
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}

void ShowLoginUI(HWND hwnd)
{
    RECT rc;
    GetClientRect(hwnd, &rc);

    hPasswordEdit = CreateWindowEx(
        WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL,
        rc.right / 2 - 150, rc.bottom / 2 - 20, 300, 24,
        hwnd, (HMENU)1000, NULL, NULL);

    hUnlockButton = CreateWindow(
        L"BUTTON", L"Unlock",
        WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
        rc.right / 2 - 60, rc.bottom / 2 + 20, 120, 28,
        hwnd, (HMENU)1001, NULL, NULL);

    SendMessage(hPasswordEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hUnlockButton, WM_SETFONT, (WPARAM)hFont, TRUE);
}

void DestroyLoginUI(void)
{
    DestroyWindow(hPasswordEdit);
    DestroyWindow(hUnlockButton);
}

void ShowEditorUI(HWND hwnd)
{
    RECT rc;
    GetClientRect(hwnd, &rc);

    hEdit = CreateWindowEx(
        WS_EX_CLIENTEDGE, MSFTEDIT_CLASS, L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
            ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
        10, 10, rc.right - 20, rc.bottom - 60,
        hwnd, (HMENU)2000, NULL, NULL);

    hSaveButton = CreateWindow(
        L"BUTTON", L"Save Encrypted",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        rc.right - 160, rc.bottom - 40, 140, 28,
        hwnd, (HMENU)1002, NULL, NULL);

    hLogoutButton = CreateWindow(
        L"BUTTON", L"Logout",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        10, rc.bottom - 40, 100, 28,
        hwnd, (HMENU)1003, NULL, NULL);

    SendMessage(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hSaveButton, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hLogoutButton, WM_SETFONT, (WPARAM)hFont, TRUE);
}

void DestroyEditorUI(void)
{
    DestroyWindow(hEdit);
    DestroyWindow(hSaveButton);
    DestroyWindow(hLogoutButton);
}

void LoadAndDecryptText(HWND hEdit)
{
    char *text = ReadFileAndDecrypt(".\\", "notes.enc");
    if (!text)
    {
        // TODO error message box
        return;
    }

    wchar_t wtext[65536];
    MultiByteToWideChar(CP_UTF8, 0, text, -1, wtext, 65536);
    SetWindowTextW(hEdit, wtext);
    free(text);
}

void SaveEncryptedText(HWND hEdit)
{

    wchar_t wtext[65536];
    GetWindowTextW(hEdit, wtext, 65536);

    char text[65536];
    WideCharToMultiByte(CP_UTF8, 0, wtext, -1, text, 65536, NULL, NULL);

    if (EncryptAndSaveFile(".\\", "notes.enc", text) != 0)
    {
        //TODO ERROR messageBox
        return;
    }
}
