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

#define AUTOSAVE_TIMER_ID 42
#define AUTOSAVE_DELAY_MS 2000

typedef struct NoteEntry {
    wchar_t name[256];
    char* fileName;  // malloc'ed
    struct NoteEntry* next;
} NoteEntry;

static NoteEntry* gNotes = NULL;
static NoteEntry* gCurrentNote = NULL;
static UINT_PTR gAutoSaveTimer = 0;
static BOOL gTextChanged = FALSE;

HWND hPasswordLabel, hPasswordEdit, hPasswordEdit2, hUnlockButton;
HWND hEdit, hLogoutButton;
HFONT hFont;
BOOL isUnlocked = FALSE;

HWND hNotesList, hNewNoteButton, hDeleteNoteButton;

LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void ShowLoginUI(HWND hwnd);
void ShowEditorUI(HWND hwnd);
void DestroyLoginUI(void);
void DestroyEditorUI(void);
void LoadAndDecryptText(HWND hEdit);
void SaveEncryptedText(HWND hEdit);

static void NotesList_FreeAll(void)
{
    NoteEntry* cur = gNotes;
    while (cur) {
        NoteEntry* next = cur->next;
        if (cur->fileName) { SecureZeroMemory(cur->fileName, strlen(cur->fileName)); free(cur->fileName); }
        free(cur);
        cur = next;
    }
    gNotes = NULL;
}

static void NotesList_SaveToDisk(void)
{
    FILE* f = fopen(".\\notes.index", "w");
    if (!f) return;
    for (NoteEntry* n = gNotes; n; n = n->next)
        fwprintf(f, L"%ls\t%hs\n", n->name, n->fileName);
    fclose(f);
}

static void NotesList_LoadFromDisk(HWND hNotesList)
{
    FILE* f = _wfopen(L".\\notes.index", L"r, ccs=UTF-8");
    if (!f) return;

    wchar_t name[256];
    char fileName[512];
    while (fwscanf(f, L"%255ls\t%511s\n", name, fileName) == 2) {
        NoteEntry* n = calloc(1, sizeof(NoteEntry));
        wcscpy_s(n->name, 256, name);
        n->fileName = _strdup(fileName);
        n->next = gNotes;
        gNotes = n;

        int idx = (int)SendMessageW(hNotesList, LB_ADDSTRING, 0, (LPARAM)n->name);
        SendMessageW(hNotesList, LB_SETITEMDATA, idx, (LPARAM)n);
    }
    fclose(f);
}


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
             }
             else
             {
                 MessageBox(hwnd, L"Wrong password or failed to derive AES key.", L"Error", MB_ICONERROR);
             }

             return 0;
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
            // Auto-save current note before switching
            if (gCurrentNote && gTextChanged) {
                SaveEncryptedText(hEdit);
                gTextChanged = FALSE;
            }

            int sel = (int)SendMessage(hNotesList, LB_GETCURSEL, 0, 0);
            if (sel != LB_ERR) {
                gCurrentNote = (NoteEntry*)SendMessage(hNotesList, LB_GETITEMDATA, sel, 0);
                if (gCurrentNote) {
                    LoadAndDecryptText(hEdit);
                    gTextChanged = FALSE;
                    EnableWindow(hEdit, TRUE);
                }
            }
        }
        else if (LOWORD(wParam) == 3001) { // New Note
            wchar_t wNewName[256] = L"";
            if (DialogBoxParamW(GetModuleHandle(NULL), MAKEINTRESOURCE(101), hwnd, NewNoteDialogProc, (LPARAM)wNewName) == IDOK) {
                if (wcslen(wNewName) == 0) {
                    MessageBox(hwnd, L"Note name cannot be empty.", L"Error", MB_ICONERROR);
                    return 0;
                }

                // Check duplicates
                for (NoteEntry* n = gNotes; n; n = n->next)
                    if (_wcsicmp(n->name, wNewName) == 0) {
                        MessageBox(hwnd, L"Note already exists.", L"Error", MB_ICONERROR);
                        return 0;
                    }

                char noteNameUtf8[256];
                WideCharToMultiByte(CP_UTF8, 0, wNewName, -1, noteNameUtf8, sizeof(noteNameUtf8), NULL, NULL);
                char* fileName = NotesNameToFileName(noteNameUtf8);
                if (!fileName) {
                    MessageBox(hwnd, L"Failed to create filename.", L"Error", MB_ICONERROR);
                    return 0;
                }

                // Create note entry
                NoteEntry* n = calloc(1, sizeof(NoteEntry));
                wcscpy_s(n->name, 256, wNewName);
                n->fileName = fileName;
                n->next = gNotes;
                gNotes = n;

                int idx = (int)SendMessageW(hNotesList, LB_ADDSTRING, 0, (LPARAM)n->name);
                SendMessageW(hNotesList, LB_SETITEMDATA, idx, (LPARAM)n);
                SendMessageW(hNotesList, LB_SETCURSEL, idx, 0);

                gCurrentNote = n;
                SetWindowTextW(hEdit, L"");
                EnableWindow(hEdit, TRUE);
                gTextChanged = FALSE;
                NotesList_SaveToDisk();
            }
        }
        else if (LOWORD(wParam) == 3002) { // Delete
            int sel = (int)SendMessage(hNotesList, LB_GETCURSEL, 0, 0);
            if (sel == LB_ERR) return 0;

            NoteEntry* n = (NoteEntry*)SendMessage(hNotesList, LB_GETITEMDATA, sel, 0);
            if (!n) return 0;

            char path[MAX_PATH];
            snprintf(path, MAX_PATH, ".\\%s", n->fileName);
            DeleteFileA(path);

            SendMessage(hNotesList, LB_DELETESTRING, sel, 0);

            // Remove from linked list
            NoteEntry** prev = &gNotes;
            while (*prev && *prev != n)
                prev = &(*prev)->next;
            if (*prev) *prev = n->next;

            SecureZeroMemory(n->fileName, strlen(n->fileName));
            free(n->fileName);
            free(n);

            gCurrentNote = NULL;
            SetWindowTextW(hEdit, L"");
            EnableWindow(hEdit, FALSE);
            NotesList_SaveToDisk();
        }
        else if (HIWORD(wParam) == EN_CHANGE && (HWND)lParam == hEdit) {
            gTextChanged = TRUE;
            if (gAutoSaveTimer)
                KillTimer(hwnd, AUTOSAVE_TIMER_ID);
            gAutoSaveTimer = SetTimer(hwnd, AUTOSAVE_TIMER_ID, AUTOSAVE_DELAY_MS, NULL);
        }
        break;
        case WM_TIMER:
            if (wParam == AUTOSAVE_TIMER_ID) {
                KillTimer(hwnd, AUTOSAVE_TIMER_ID);
                gAutoSaveTimer = 0;
                if (gTextChanged && gCurrentNote) {
                    SaveEncryptedText(hEdit);
                gTextChanged = FALSE;
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

    case WM_DESTROY: {
        if (gCurrentNote && gTextChanged)
            SaveEncryptedText(hEdit);
        NotesList_SaveToDisk();
        NotesList_FreeAll();
        Logout();
        DeleteObject(hFont);
        PostQuitMessage(0);
        return 0;
    }
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
        
    NotesList_LoadFromDisk(hNotesList);
    
    EnableWindow(hEdit, FALSE);

    hLogoutButton = CreateWindow(
        L"BUTTON", L"Logout",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        rc.right - 160, rc.bottom - 30, 140, 28,
        hwnd, (HMENU)1003, NULL, NULL);

    SendMessage(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hNotesList, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hNewNoteButton, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hDeleteNoteButton, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hLogoutButton, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    int count = (int)SendMessage(hNotesList, LB_GETCOUNT, 0, 0);
    if (count == 0) {
        MessageBox(hwnd, L"No notes found. Please create a new note to begin.", L"Welcome", MB_ICONINFORMATION);
    }
}

void DestroyEditorUI(void)
{
    DestroyWindow(hEdit);
    DestroyWindow(hLogoutButton);
}

void LoadAndDecryptText(HWND hEdit)
{
    if (!gCurrentNote || !gCurrentNote->fileName || !*gCurrentNote->fileName) {
        SetWindowTextW(hEdit, L"");
        return;
    }

    char* text = ReadFileAndDecrypt(".\\", gCurrentNote->fileName);
    if (!text) {
        SetWindowTextW(hEdit, L"");
        return;
    }

    int wlen = MultiByteToWideChar(CP_UTF8, 0, text, -1, NULL, 0);
    wchar_t* wtext = malloc(wlen * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, text, -1, wtext, wlen);
    SetWindowTextW(hEdit, wtext);

    SecureZeroMemory(text, strlen(text));
    free(text);
    free(wtext);
}

void SaveEncryptedText(HWND hEdit)
{
    if (!gCurrentNote || !gCurrentNote->fileName || !*gCurrentNote->fileName)
        return;

    int wlen = GetWindowTextLengthW(hEdit);
    if (wlen < 0) return;

    wchar_t* wtext = malloc((wlen + 1) * sizeof(wchar_t));
    if (!wtext) return;
    GetWindowTextW(hEdit, wtext, wlen + 1);

    int buflen = WideCharToMultiByte(CP_UTF8, 0, wtext, -1, NULL, 0, NULL, NULL);
    char* text = malloc(buflen);
    if (!text) { free(wtext); return; }
    WideCharToMultiByte(CP_UTF8, 0, wtext, -1, text, buflen, NULL, NULL);

    if (!EncryptAndSaveFile(".\\", gCurrentNote->fileName, text))
        MessageBox(NULL, L"Failed to save encrypted note.", L"Error", MB_ICONERROR);

    SecureZeroMemory(text, buflen);
    SecureZeroMemory(wtext, (wlen + 1) * sizeof(wchar_t));
    free(text);
    free(wtext);
}


