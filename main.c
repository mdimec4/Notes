#define _UNICODE
#include <windows.h>
#include <richedit.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "core.h"

#ifdef _MSC_VER
#pragma comment(lib, "Comctl32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Gdi32.lib")
#pragma comment(lib, "Advapi32.lib")
#endif

HWND hPasswordLabel, hPasswordEdit, hPasswordEdit2, hUnlockButton;
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
    if (Init() != 0)
    {
        fprintf(stderr, "Failed to init app!");
        return 1;
    }
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
            int len = GetWindowTextLengthW(hPasswordEdit) + 1;
            wchar_t* pwbuf = (wchar_t*)malloc(len * sizeof(wchar_t));
            GetWindowTextW(hPasswordEdit, pwbuf, len);

            int buflen = WideCharToMultiByte(CP_UTF8, 0, pwbuf, -1, NULL, 0, NULL, NULL);
            char* password = (char*)malloc(buflen);
            WideCharToMultiByte(CP_UTF8, 0, pwbuf, -1, password, buflen, NULL, NULL);

             // Clear the password field immediately after copying
             SetWindowTextW(hPasswordEdit, L"");
             
             if (hPasswordEdit2 != NULL)
             {             
                 if (strlen(password) < 21)
                 {
                     MessageBox(hwnd, L"Selected password is too short. Password must be at least 21 characters long!", L"Error", MB_ICONERROR);
                     
                     SetWindowTextW(hPasswordEdit2, L"");
                     
                     // Securely wipe password buffers
                     SecureZeroMemory(pwbuf, len * sizeof(wchar_t));
                     SecureZeroMemory(password, buflen);

                     free(pwbuf);
                     free(password);
                     return 0;
                }
                int len2 = GetWindowTextLengthW(hPasswordEdit2) + 1;
                wchar_t* pwbuf2 = (wchar_t*)malloc(len2 * sizeof(wchar_t));
                GetWindowTextW(hPasswordEdit2, pwbuf2, len2);

                int buflen2 = WideCharToMultiByte(CP_UTF8, 0, pwbuf2, -1, NULL, 0, NULL, NULL);
                char* password2 = (char*)malloc(buflen2);
                WideCharToMultiByte(CP_UTF8, 0, pwbuf2, -1, password2, buflen2, NULL, NULL);
                
                // Clear the password field immediately after copying
                SetWindowTextW(hPasswordEdit2, L"");
                
                if (buflen != buflen2 || strncmp(password, password2, MIN(buflen, buflen2) != 0))
                {
                    MessageBox(hwnd, L"Passwords don't match!", L"Error", MB_ICONERROR);
                    
                    SecureZeroMemory(pwbuf, len * sizeof(wchar_t));
                    SecureZeroMemory(password, buflen);
                    SecureZeroMemory(pwbuf2, len2 * sizeof(wchar_t));
                    SecureZeroMemory(password2, buflen2);

                    free(pwbuf);
                    free(password);
                    free(pwbuf2);
                    free(password2);
                    return 0;
                }
                
                // Securely wipe password buffers
                SecureZeroMemory(pwbuf2, len * sizeof(wchar_t));
                SecureZeroMemory(password2, buflen2);

                free(pwbuf2);
                free(password2);
            }

             int success = CheckPasswordAndDeriveAesKey(password, ".\\", "verifier.dat");

             // Securely wipe password buffers
             SecureZeroMemory(pwbuf, len * sizeof(wchar_t));
             SecureZeroMemory(password, buflen);

             free(pwbuf);
             free(password);

             if (success)
             {
                 isUnlocked = TRUE;
                 DestroyLoginUI();
                 ShowEditorUI(hwnd);
                 LoadAndDecryptText(hEdit);
             }
             else
             {
                 MessageBox(hwnd, L"Wrong password or failed to derive AES key.", L"Error", MB_ICONERROR);
             }

             return 0;
        }
        else if (LOWORD(wParam) == 1002) // Save
        {
            SaveEncryptedText(hEdit);
        }
        else if (LOWORD(wParam) == 1003) // Logout
        {
            DestroyEditorUI();
            Logout();
            isUnlocked = FALSE;
            ShowLoginUI(hwnd);
            return 0;
        }
        break;
    case WM_CTLCOLORSTATIC:
    {
         HDC hdc = (HDC)wParam;
         SetBkMode(hdc, TRANSPARENT);
         return (INT_PTR)GetStockObject(NULL_BRUSH);
    }
    case WM_SIZE:
    {
        RECT rc;
        GetClientRect(hwnd, &rc);
        if (isUnlocked)
        {
            MoveWindow(hEdit, 10, 10, rc.right - 20, rc.bottom - 60, TRUE);
            MoveWindow(hSaveButton, rc.right - 160, rc.bottom - 40, 140, 28, TRUE);
            MoveWindow(hLogoutButton, 10, rc.bottom - 40, 100, 28, TRUE);
        }
        else
        {
            MoveWindow(hPasswordLabel, rc.right / 2 - 150, rc.bottom / 2 - 60, hPasswordEdit2 == NULL ? 300 : 500, 24, TRUE);
            MoveWindow(hPasswordEdit, rc.right / 2 - 150, rc.bottom / 2 - 20, 300, 24, TRUE);
            if (hPasswordEdit2 != NULL) MoveWindow(hPasswordEdit2, rc.right / 2 - 150, rc.bottom / 2 + 20, 300, 24, TRUE);
            MoveWindow(hUnlockButton, rc.right / 2 - 60, rc.bottom / 2 + 45, 120, 28, TRUE);
        }
        return 0;
    }

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
    
    int isPasswordSet = IsPasswordIsSetSplitPath(".\\", "verifier.dat");
    
    hPasswordLabel = CreateWindow(L"static", L"ST_U",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        rc.right / 2 - 150, rc.bottom / 2 - 60, isPasswordSet ? 300 : 500, 24,
        hwnd, (HMENU)(501),
        NULL, NULL);
    SetWindowText(hPasswordLabel, isPasswordSet ? L"Password:" : L"New password: (Use letters, numbers and special characters)");

    hPasswordEdit = CreateWindowEx(
        WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL,
        rc.right / 2 - 150, rc.bottom / 2 - 20, 300, 24,
        hwnd, (HMENU)1000, NULL, NULL);
        

    if (!isPasswordSet)
    {
        hPasswordEdit2 = CreateWindowEx(
            WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL,
            rc.right / 2 - 150, rc.bottom / 2 + 20, 300, 24,
            hwnd, (HMENU)1000, NULL, NULL);
    }
    else
        hPasswordEdit2 = NULL;

    hUnlockButton = CreateWindow(
        L"BUTTON", isPasswordSet ? L"Unlock" : L"Set password",
        WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
        rc.right / 2 - 60, rc.bottom / 2 + 45, 120, 28,
        hwnd, (HMENU)1001, NULL, NULL);

    SendMessage(hPasswordLabel, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hPasswordEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
    if (hPasswordEdit2 != NULL) SendMessage(hPasswordEdit2, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hUnlockButton, WM_SETFONT, (WPARAM)hFont, TRUE);
}

void DestroyLoginUI(void)
{
    DestroyWindow(hPasswordLabel);
    DestroyWindow(hPasswordEdit);
    if (hPasswordEdit2 != NULL) DestroyWindow(hPasswordEdit2);
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
    // Read and decrypt the note
    char* text = ReadFileAndDecrypt(".\\", "notes.enc");
    if (!text) {
        MessageBox(NULL, L"Failed to load or decrypt the note.", L"Error", MB_ICONERROR);
        return;
    }

    // Convert to wide string
    int wlen = MultiByteToWideChar(CP_UTF8, 0, text, -1, NULL, 0);
    if (wlen <= 0) {
        SecureZeroMemory(text, strlen(text));
        free(text);
        MessageBox(NULL, L"Failed to convert note to Unicode.", L"Error", MB_ICONERROR);
        return;
    }

    wchar_t* wtext = (wchar_t*)malloc(wlen * sizeof(wchar_t));
    if (!wtext) {
        SecureZeroMemory(text, strlen(text));
        free(text);
        return;
    }

    MultiByteToWideChar(CP_UTF8, 0, text, -1, wtext, wlen);
    SetWindowTextW(hEdit, wtext);

    // Securely wipe buffers
    SecureZeroMemory(wtext, wlen * sizeof(wchar_t));
    SecureZeroMemory(text, strlen(text));

    free(wtext);
    free(text);
}


void SaveEncryptedText(HWND hEdit)
{
    // Get text length
    int wlen = GetWindowTextLengthW(hEdit);
    if (wlen == 0) return;

    // Allocate buffer for wide text
    wchar_t* wtext = (wchar_t*)malloc((wlen + 1) * sizeof(wchar_t));
    if (!wtext) return;

    GetWindowTextW(hEdit, wtext, wlen + 1);

    // Convert to UTF-8
    int buflen = WideCharToMultiByte(CP_UTF8, 0, wtext, -1, NULL, 0, NULL, NULL);
    if (buflen <= 0) {
        SecureZeroMemory(wtext, (wlen + 1) * sizeof(wchar_t));
        free(wtext);
        return;
    }

    char* text = (char*)malloc(buflen);
    if (!text) {
        SecureZeroMemory(wtext, (wlen + 1) * sizeof(wchar_t));
        free(wtext);
        return;
    }

    WideCharToMultiByte(CP_UTF8, 0, wtext, -1, text, buflen, NULL, NULL);

    // Encrypt and save
    if (EncryptAndSaveFile(".\\", "notes.enc", text) == 0) {
        MessageBox(NULL, L"Failed to save encrypted note.", L"Error", MB_ICONERROR);
    }

    // Securely wipe buffers
    SecureZeroMemory(text, buflen);
    SecureZeroMemory(wtext, (wlen + 1) * sizeof(wchar_t));

    free(text);
    free(wtext);
}

