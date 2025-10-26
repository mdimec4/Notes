#ifndef CORE_H
#define CORE_H
void EncryptAndSaveFile(char* saveDirPath, char* fileName, char* text);
char* ReadFileAndDecrypt(char* loadDirPath, char* fileName);
#endif