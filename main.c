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

HWND hNotesList, hNewNoteButton, hDeleteNoteButton;
wchar_t currentNoteName[256] = L"";

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

INT_PTR CALLBACK NewNoteDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_INITDIALOG:
        // Save pointer to user buffer (passed via lParam)
        SetWindowLongPtr(hDlg, GWLP_USERDATA, (LONG_PTR)lParam);
        return TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK) {
            wchar_t* nameBuf = (wchar_t*)GetWindowLongPtr(hDlg, GWLP_USERDATA);
            if (nameBuf) {
                GetDlgItemTextW(hDlg, 1000, nameBuf, 255);
            }
            EndDialog(hDlg, IDOK);
            return TRUE;
        }
        else if (LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
        break;
    }
    return FALSE;
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
                
                if (buflen != buflen2 || strncmp(password, password2, MIN(buflen, buflen2)) != 0)
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
        else if (LOWORD(wParam) == 3000 && HIWORD(wParam) == LBN_SELCHANGE) {
            int sel = (int)SendMessage(hNotesList, LB_GETCURSEL, 0, 0);
            if (sel != LB_ERR) {
                wchar_t wNote[256];
                SendMessage(hNotesList, LB_GETTEXT, sel, (LPARAM)wNote);

                wcscpy_s(currentNoteName, 256, wNote);
                LoadAndDecryptText(hEdit);

                EnableWindow(hEdit, TRUE);
                EnableWindow(hSaveButton, TRUE);
            }
        }
        else if (LOWORD(wParam) == 3001) { // New Note
            wchar_t wNewName[256] = L"";

            if (DialogBoxParamW(GetModuleHandle(NULL), MAKEINTRESOURCE(101), hwnd, NewNoteDialogProc, (LPARAM)wNewName) == IDOK) {
                // Trim whitespace
                for (wchar_t* p = wNewName; *p; ++p) {
                    if (*p == L'\r' || *p == L'\n') *p = 0;
                }

                // Check for empty
                if (wcslen(wNewName) == 0) {
                    MessageBox(hwnd, L"Note name cannot be empty.", L"Error", MB_ICONERROR);
                    return 0;
                }

                // Check duplicates
                int count = (int)SendMessage(hNotesList, LB_GETCOUNT, 0, 0);
                for (int i = 0; i < count; i++) {
                    wchar_t existing[256];
                    SendMessage(hNotesList, LB_GETTEXT, i, (LPARAM)existing);
                    if (_wcsicmp(existing, wNewName) == 0) {
                        MessageBox(hwnd, L"A note with this name already exists.", L"Error", MB_ICONERROR);
                        return 0;
                    }
                }

                // Add and select
                SendMessage(hNotesList, LB_ADDSTRING, 0, (LPARAM)wNewName);
                SendMessage(hNotesList, LB_SETCURSEL, count, 0);
                wcscpy_s(currentNoteName, 256, wNewName);
                SetWindowTextW(hEdit, L"");

                // Enable editor & save
                EnableWindow(hEdit, TRUE);
                EnableWindow(hSaveButton, TRUE);
            }
        }
        else if (LOWORD(wParam) == 3002) { // Delete Note
            int sel = (int)SendMessage(hNotesList, LB_GETCURSEL, 0, 0);
            if (sel != LB_ERR) {
                wchar_t wNote[256];
                SendMessage(hNotesList, LB_GETTEXT, sel, (LPARAM)wNote);

                int confirm = MessageBox(hwnd, L"Delete this note permanently?", L"Confirm", MB_YESNO | MB_ICONWARNING);
                if (confirm == IDYES) {
                    char noteNameUtf8[256];
                    WideCharToMultiByte(CP_UTF8, 0, wNote, -1, noteNameUtf8, sizeof(noteNameUtf8), NULL, NULL);
                    char* fileName = NotesNameToFileName(noteNameUtf8);
                    if (fileName) {
                        char path[MAX_PATH];
                        snprintf(path, MAX_PATH, ".\\%s", fileName);
                        DeleteFileA(path);
                        free(fileName);
                    }
                    SendMessage(hNotesList, LB_DELETESTRING, sel, 0);
                    SetWindowTextW(hEdit, L"");
                }
            }
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
        Logout();
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

    int listWidth = 200;

    // Notes list on the left
    hNotesList = CreateWindowEx(
        WS_EX_CLIENTEDGE, L"LISTBOX", NULL,
        WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_VSCROLL,
        10, 10, listWidth - 20, rc.bottom - 80,
        hwnd, (HMENU)3000, NULL, NULL);

    // "New Note" and "Delete Note" buttons below the list
    hNewNoteButton = CreateWindow(
        L"BUTTON", L"New Note",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        10, rc.bottom - 60, (listWidth - 30) / 2, 28,
        hwnd, (HMENU)3001, NULL, NULL);

    hDeleteNoteButton = CreateWindow(
        L"BUTTON", L"Delete",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        10 + (listWidth - 30) / 2 + 10, rc.bottom - 60, (listWidth - 30) / 2, 28,
        hwnd, (HMENU)3002, NULL, NULL);

    // Rich Edit for note text
    hEdit = CreateWindowEx(
        WS_EX_CLIENTEDGE, MSFTEDIT_CLASS, L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
        ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
        listWidth, 10, rc.right - listWidth - 20, rc.bottom - 80,
        hwnd, (HMENU)2000, NULL, NULL);
        
        EnableWindow(hEdit, FALSE);
        EnableWindow(hSaveButton, FALSE);

    // Save and Logout
    hSaveButton = CreateWindow(
        L"BUTTON", L"Save Encrypted",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        rc.right - 160, rc.bottom - 60, 140, 28,
        hwnd, (HMENU)1002, NULL, NULL);

    hLogoutButton = CreateWindow(
        L"BUTTON", L"Logout",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        rc.right - 160, rc.bottom - 30, 140, 28,
        hwnd, (HMENU)1003, NULL, NULL);

    SendMessage(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hNotesList, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hNewNoteButton, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hDeleteNoteButton, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hSaveButton, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hLogoutButton, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Populate notes list
    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(".\\*.enc", &ffd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            char* noteName = FileNameToNotesName(ffd.cFileName);
            if (noteName) {
                int wlen = MultiByteToWideChar(CP_UTF8, 0, noteName, -1, NULL, 0);
                wchar_t* wNote = malloc(wlen * sizeof(wchar_t));
                MultiByteToWideChar(CP_UTF8, 0, noteName, -1, wNote, wlen);
                SendMessageW(hNotesList, LB_ADDSTRING, 0, (LPARAM)wNote);
                free(wNote);
                free(noteName);
            }
        } while (FindNextFileA(hFind, &ffd));
        FindClose(hFind);
    }
    
    int count = (int)SendMessage(hNotesList, LB_GETCOUNT, 0, 0);
    if (count == 0) {
        MessageBox(hwnd, L"No notes found. Please create a new note to begin.", L"Welcome", MB_ICONINFORMATION);
    }
}

void DestroyEditorUI(void)
{
    DestroyWindow(hEdit);
    DestroyWindow(hSaveButton);
    DestroyWindow(hLogoutButton);
}

void LoadAndDecryptText(HWND hEdit)
{
    if (wcslen(currentNoteName) == 0)
        return;

    char noteNameUtf8[256];
    WideCharToMultiByte(CP_UTF8, 0, currentNoteName, -1, noteNameUtf8, sizeof(noteNameUtf8), NULL, NULL);

    char* fileName = NotesNameToFileName(noteNameUtf8);
    if (!fileName) return;

    char* text = ReadFileAndDecrypt(".\\", fileName);
    free(fileName);

    if (!text) {
        SetWindowTextW(hEdit, L"");
        return;
    }

    int wlen = MultiByteToWideChar(CP_UTF8, 0, text, -1, NULL, 0);
    wchar_t* wtext = malloc(wlen * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, text, -1, wtext, wlen);
    SetWindowTextW(hEdit, wtext);

    free(wtext);
    SecureZeroMemory(text, strlen(text));
    free(text);
}



void SaveEncryptedText(HWND hEdit)
{
    if (wcslen(currentNoteName) == 0)
        return;

    // Dynamically query text length
    int wlen = GetWindowTextLengthW(hEdit);
    if (wlen <= 0)
        return;

    wchar_t* wtext = (wchar_t*)malloc((wlen + 1) * sizeof(wchar_t));
    if (!wtext)
        return;

    GetWindowTextW(hEdit, wtext, wlen + 1);

    // Convert note name to UTF-8 filename
    char noteNameUtf8[256];
    WideCharToMultiByte(CP_UTF8, 0, currentNoteName, -1, noteNameUtf8, sizeof(noteNameUtf8), NULL, NULL);
    char* fileName = NotesNameToFileName(noteNameUtf8);
    if (!fileName) {
        free(wtext);
        return;
    }

    // Convert note text to UTF-8
    int buflen = WideCharToMultiByte(CP_UTF8, 0, wtext, -1, NULL, 0, NULL, NULL);
    if (buflen <= 0) {
        free(fileName);
        free(wtext);
        return;
    }

    char* text = (char*)malloc(buflen);
    if (!text) {
        free(fileName);
        free(wtext);
        return;
    }

    WideCharToMultiByte(CP_UTF8, 0, wtext, -1, text, buflen, NULL, NULL);

    if (!EncryptAndSaveFile(".\\", fileName, text)) {
        MessageBox(NULL, L"Failed to save encrypted note.", L"Error", MB_ICONERROR);
    }

    // Securely wipe memory
    SecureZeroMemory(text, buflen);
    SecureZeroMemory(wtext, (wlen + 1) * sizeof(wchar_t));

    free(text);
    free(wtext);
    free(fileName);
}

