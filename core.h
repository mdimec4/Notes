#ifndef CORE_H
#define CORE_H
int EncryptAndSaveFile(const char* saveDirPath, const char* fileName, const char* text);
char* ReadFileAndDecrypt(const char* loadDirPath, const char* fileName);
#endif