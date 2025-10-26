//#define UNICODE
#define _UNICODE
#include <windows.h>
#include <commctrl.h>
#include <richedit.h>
#include <shlwapi.h>
#include <tchar.h>
#include <assert.h>
#include <stdio.h>

#include "core.h"

//#pragma comment(lib, "Comctl32.lib")
//#pragma comment(lib, "Shlwapi.lib")

// Window globals
HWND hEdit;
HWND hSaveButton;
HFONT hFont;

// Forward declarations
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void LoadAndDecryptText(HWND hEdit);
void SaveEncryptedText(HWND hEdit);

// Entry point
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
    // Load RichEdit for multiline text
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
        0,
        CLASS_NAME,
        L"Secure Notes",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 700, 500,
        NULL,
        NULL,
        hInstance,
        NULL);

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
        RECT rcClient;
        GetClientRect(hwnd, &rcClient);

        hEdit = CreateWindowEx(
            WS_EX_CLIENTEDGE, MSFTEDIT_CLASS, L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
                ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
            10, 10, rcClient.right - 20, rcClient.bottom - 60,
            hwnd, (HMENU)1001, ((LPCREATESTRUCT)lParam)->hInstance, NULL);

        hSaveButton = CreateWindow(
            L"BUTTON", L"Save Encrypted",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            rcClient.right - 160, rcClient.bottom - 40, 140, 28,
            hwnd, (HMENU)1002, ((LPCREATESTRUCT)lParam)->hInstance, NULL);

        // Apply font
        LOGFONT lf = {0};
        lf.lfHeight = -16;
        wcscpy_s(lf.lfFaceName, LF_FACESIZE, L"Segoe UI");
        hFont = CreateFontIndirect(&lf);
        SendMessage(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessage(hSaveButton, WM_SETFONT, (WPARAM)hFont, TRUE);

        LoadAndDecryptText(hEdit);
        return 0;
    }

    case WM_SIZE:
    {
        RECT rc;
        GetClientRect(hwnd, &rc);
        MoveWindow(hEdit, 10, 10, rc.right - 20, rc.bottom - 60, TRUE);
        MoveWindow(hSaveButton, rc.right - 160, rc.bottom - 40, 140, 28, TRUE);
        return 0;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == 1002)
        {
            SaveEncryptedText(hEdit);
            MessageBox(hwnd, L"Encrypted note saved successfully.", L"Success", MB_ICONINFORMATION);
            return 0;
        }
        break;

    case WM_DESTROY:
        DeleteObject(hFont);
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}

void LoadAndDecryptText(HWND hEdit)
{
    char *text = ReadFileAndDecrypt(".\\", "notes.enc");
    if (!text)
        return;

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

    EncryptAndSaveFile(".\\", "notes.enc", text);
}
