#define _UNICODE
#include <windows.h>
#include <richedit.h>
#include <commdlg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "core.h"
#include "mdlinkedlist.h"

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
} NoteEntry;

struct FileEntry {
    char fileName[MAX_PATH];
    FILETIME ftLastWrite;
};

static md_linked_list_el* gNotes = NULL;
static NoteEntry* gCurrentNote = NULL;
static UINT_PTR gAutoSaveTimer = 0;
static BOOL gTextChanged = FALSE;

HWND hPasswordLabel, hPasswordEdit, hPasswordEdit2, hUnlockButton;
HWND hEdit, hLogoutButton;
HFONT hFont;
BOOL isUnlocked = FALSE;

HWND hNotesList, hNewNoteButton, hDeleteNoteButton;

HWND hExportButton;

LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void ShowLoginUI(HWND hwnd);
void ShowEditorUI(HWND hwnd);
void DestroyLoginUI(void);
void DestroyEditorUI(void);
void LoadAndDecryptText(HWND hEdit);
void SaveEncryptedText(HWND hEdit);

static void NotesEntry_Free(void* data)
{
    if (!data)
        return;
    NoteEntry* ne = (NoteEntry*)data;
    SecureZeroMemory(ne->fileName, strlen(ne->fileName));
    SecureZeroMemory(ne->name, sizeof(ne->name));
    free(ne->fileName);
    free(data);
}

static void NotesList_FreeAll(void)
{
    if (!gNotes)
        return;
    md_linked_list_free_all(gNotes, NotesEntry_Free);
    gNotes = NULL;
}

static int CompareFileEntry(const void* a, const void* b)
{
    const struct FileEntry* fa = (const struct FileEntry*)a;
    const struct FileEntry* fb = (const struct FileEntry*)b;
    return CompareFileTime(&fb->ftLastWrite, &fa->ftLastWrite);
}

static void NotesList_LoadFromDir(HWND hNotesList)
{
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(".\\*.enc", &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return;

    struct FileEntry files[512];
    int fileCount = 0;

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            strncpy(files[fileCount].fileName, fd.cFileName, MAX_PATH - 1);
            files[fileCount].fileName[MAX_PATH - 1] = 0;
            files[fileCount].ftLastWrite = fd.ftLastWriteTime;
            fileCount++;
        }
    } while (FindNextFileA(hFind, &fd) && fileCount < 512);

    FindClose(hFind);

    /* Sort by modification time, newest first */
    qsort(files, fileCount, sizeof(files[0]), CompareFileEntry);

    NotesList_FreeAll();
    SendMessageW(hNotesList, LB_RESETCONTENT, 0, 0);

    for (int i = 0; i < fileCount; i++) {
        char* noteNameUtf8 = FileNameToNotesName(files[i].fileName);
        if (!noteNameUtf8)
            continue;

        int wlen = MultiByteToWideChar(CP_UTF8, 0, noteNameUtf8, -1, NULL, 0);
        if (wlen <= 0) {
            SecureZeroMemory(noteNameUtf8, strlen(noteNameUtf8));
            free(noteNameUtf8);
            continue;
        }

        wchar_t* wname = (wchar_t*)malloc(wlen * sizeof(wchar_t));
        if (!wname) {
            SecureZeroMemory(noteNameUtf8, strlen(noteNameUtf8));
            free(noteNameUtf8);
            continue;
        }

        MultiByteToWideChar(CP_UTF8, 0, noteNameUtf8, -1, wname, wlen);

        NoteEntry* n = (NoteEntry*)calloc(1, sizeof(NoteEntry));
        if (!n) {
            SecureZeroMemory(noteNameUtf8, strlen(noteNameUtf8));
            free(noteNameUtf8);
            free(wname);
            continue;
        }

        wcscpy_s(n->name, 256, wname);
        n->fileName = _strdup(files[i].fileName);
        
        gNotes = md_linked_list_add(gNotes, n);

        int idx = (int)SendMessageW(hNotesList, LB_ADDSTRING, 0, (LPARAM)n->name);
        SendMessageW(hNotesList, LB_SETITEMDATA, idx, (LPARAM)n);

        SecureZeroMemory(noteNameUtf8, strlen(noteNameUtf8));
        free(noteNameUtf8);
        free(wname);
    }
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

static void WipeWindowText(HWND wnd)
{
    if (!wnd || !IsWindow(wnd)) 
        return;
        
    int len = GetWindowTextLengthW(wnd);
    if (len > 0) {
        wchar_t* buf = (wchar_t*)malloc((len + 1) * sizeof(wchar_t));
        if (buf) {
            GetWindowTextW(wnd, buf, len + 1);
            SecureZeroMemory(buf, (len + 1) * sizeof(wchar_t));
            free(buf);
        }
    }
    SetWindowTextW(wnd, L"");
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
             WipeWindowText(hPasswordEdit);
             
             if (hPasswordEdit2 != NULL)
             {             
                 if (strlen(password) < 21)
                 {
                     MessageBox(hwnd, L"Selected password is too short. Password must be at least 21 characters long!", L"Error", MB_ICONERROR);
                     
                     WipeWindowText(hPasswordEdit2);
                     
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
                WipeWindowText(hPasswordEdit2);
                
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
            if (gCurrentNote) {
                /* Save what’s in the editor, even if user didn't type */
                SaveEncryptedText(hEdit);
            }
            
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
                SaveEncryptedText(hEdit);
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
                for (md_linked_list_el* el = gNotes; el; el = el->next) {
                    NoteEntry* ne = (NoteEntry*)el->data;
                    if (_wcsicmp(ne->name, wNewName) == 0) {
                        MessageBox(hwnd, L"Note already exists.", L"Error", MB_ICONERROR);
                        return 0;
                    }
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
               
               // prepend to linked list
               md_linked_list_el* new_el = calloc(1, sizeof(md_linked_list_el));
               new_el->prev = NULL;
               new_el->next = gNotes;
               new_el->data = n;
               gNotes->prev = new_el;
               gNotes = new_el;

                // re-populate notes list
                SendMessageW(hNotesList, LB_RESETCONTENT, 0, 0);
                BOOL isNewElement = TRUE;
                for(md_linked_list_el* el = gNotes; el; el = el->next){
                    NoteEntry* ne = (NoteEntry*)el->data;
                    
                    int idx = (int)SendMessageW(hNotesList, LB_ADDSTRING, 0, (LPARAM)ne->name);
                    SendMessageW(hNotesList, LB_SETITEMDATA, idx, (LPARAM)ne);
                    if (isNewElement)
                    {
                        SendMessageW(hNotesList, LB_SETCURSEL, idx, 0);
                        isNewElement = FALSE;
                    }
                }
                    

                gCurrentNote = n;
                SetWindowTextW(hEdit, L"");
                EnableWindow(hEdit, TRUE);
                gTextChanged = FALSE;
                EncryptAndSaveFile(".\\", gCurrentNote->fileName, "");
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
            md_linked_list_el* remove_el = gNotes;
            while(remove_el && remove_el->data != n) remove_el = remove_el-> next;
            if (remove_el)
                gNotes = md_linked_list_remove(gNotes, remove_el, NotesEntry_Free);

            gCurrentNote = NULL;
            WipeWindowText(hEdit);
            EnableWindow(hEdit, FALSE);
        }
        else if (LOWORD(wParam) == 3003) { // EXPORT
            char* suggestedName = MakeSecureNotesZipFilename();

            // Convert UTF-8 → UTF-16 for Windows dialog
            wchar_t wSuggested[260];
            MultiByteToWideChar(CP_UTF8, 0, suggestedName, -1, wSuggested, 260);
            free(suggestedName);

            OPENFILENAMEW ofn;
            ZeroMemory(&ofn, sizeof(ofn));
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hwnd;
            ofn.lpstrFile = wSuggested;
            ofn.nMaxFile = ARRAYSIZE(wSuggested);
            ofn.lpstrFilter = L"Zip Files (*.zip)\0*.zip\0All Files (*.*)\0*.*\0";
            ofn.nFilterIndex = 1;
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;

            if (GetSaveFileNameW(&ofn)) {
                // Convert chosen path back to UTF-8 for your core ExportToZip()
                char targetPath[512];
                WideCharToMultiByte(CP_UTF8, 0, ofn.lpstrFile, -1, targetPath, sizeof(targetPath), NULL, NULL);

                if (ExportToZip(".\\", targetPath, "verifier.dat") != 0)
                {
                     MessageBox(hwnd, L"Failed to export data.", L"Error", MB_ICONERROR);
                     return 0;
                }
            }
        }
        else if (HIWORD(wParam) == EN_CHANGE && (HWND)lParam == hEdit) {
            gTextChanged = TRUE;

            if (gAutoSaveTimer)
                KillTimer(NULL, AUTOSAVE_TIMER_ID);  // use thread timer

            gAutoSaveTimer = SetTimer(
                NULL,                      // NULL = thread timer (not window-specific)
                AUTOSAVE_TIMER_ID,
                AUTOSAVE_DELAY_MS,
                NULL
            );
        }
        break;
    case WM_TIMER:
        if (wParam == AUTOSAVE_TIMER_ID) {
            KillTimer(NULL, AUTOSAVE_TIMER_ID);  // thread timer
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
            int listWidth = 200;
            
            MoveWindow(hNotesList, 10, 10, listWidth - 20, rc.bottom - 80, TRUE);
            MoveWindow(hNewNoteButton, 10, rc.bottom - 60, (listWidth - 30) / 2, 28, TRUE);
            MoveWindow(hDeleteNoteButton, 10 + (listWidth - 30) / 2 + 10, rc.bottom - 60, (listWidth - 30) / 2, 28, TRUE);
            MoveWindow(hNotesList, 10, 10, listWidth - 20, rc.bottom - 80, TRUE);
            MoveWindow(hEdit, listWidth, 10, rc.right - listWidth - 20, rc.bottom - 80, TRUE);
            MoveWindow(hExportButton, rc.right - 304, rc.bottom - 30, 140, 28, TRUE);
            MoveWindow(hLogoutButton, rc.right - 160, rc.bottom - 30, 140, 28, TRUE);
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
        {
            SaveEncryptedText(hEdit);
            gTextChanged = FALSE;
        }
        NotesList_FreeAll();
        
        if (hEdit && IsWindow(hEdit)) {
            WipeWindowText(hEdit);
            DestroyWindow(hEdit);
        }
        
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
            hwnd, (HMENU)1123, NULL, NULL);
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
        
    // Subscribe to EN_CHANGE notifications
    SendMessage(hEdit, EM_SETEVENTMASK, 0, ENM_CHANGE);
    
    NotesList_LoadFromDir(hNotesList);
    
    EnableWindow(hEdit, FALSE);

    hExportButton = CreateWindow(
        L"BUTTON", L"Export data",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        rc.right - 304, rc.bottom - 30, 140, 28,
        hwnd, (HMENU)3003, NULL, NULL);
        
    hLogoutButton = CreateWindow(
        L"BUTTON", L"Logout",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        rc.right - 160, rc.bottom - 30, 140, 28,
        hwnd, (HMENU)1003, NULL, NULL);

    SendMessage(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hNotesList, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hNewNoteButton, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hDeleteNoteButton, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hExportButton, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hLogoutButton, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    int count = (int)SendMessage(hNotesList, LB_GETCOUNT, 0, 0);
    if (count == 0) {
        MessageBox(hwnd, L"No notes found. Please create a new note to begin.", L"Welcome", MB_ICONINFORMATION);
    }
}

void DestroyEditorUI(void)
{
    // Stop any pending autosave timer
    if (gAutoSaveTimer) {
        KillTimer(NULL, AUTOSAVE_TIMER_ID); // or store hwnd in a global
        gAutoSaveTimer = 0;
    }

    // Securely clear text before destroying the editor control
    if (hEdit && IsWindow(hEdit)) {
        WipeWindowText(hEdit);
        DestroyWindow(hEdit);
        hEdit = NULL;
    }

    // Destroy all remaining editor UI elements
    if (hLogoutButton && IsWindow(hLogoutButton)) {
        DestroyWindow(hLogoutButton);
        hLogoutButton = NULL;
    }

    if (hNotesList && IsWindow(hNotesList)) {
        DestroyWindow(hNotesList);
        hNotesList = NULL;
    }

    if (hNewNoteButton && IsWindow(hNewNoteButton)) {
        DestroyWindow(hNewNoteButton);
        hNewNoteButton = NULL;
    }
    
    if (hDeleteNoteButton && IsWindow(hDeleteNoteButton)) {
        DestroyWindow(hDeleteNoteButton);
        hDeleteNoteButton = NULL;
    }
    
    if (hExportButton && IsWindow(hExportButton)) {
        DestroyWindow(hExportButton);
        hExportButton = NULL;
    }

    NotesList_FreeAll();
    
    // Reset globals
    gCurrentNote = NULL;
    gTextChanged = FALSE;
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
