#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#ifdef WIN32
//#define _WINSOCKAPI_   // Prevent conflicts with sys/select.h
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shlwapi.h>
#include <wincrypt.h>

#include <io.h>
#define F_OK 0
#define access _access
#endif


#include "aes.h"

unsigned char key[AES_KEYLEN] = ""; // 32 bytes
unsigned char iv[AES_BLOCKLEN] = "0123456789012345";                    // 16 bytes

struct AES_ctx encryption_ctx;

static char* JonPath(const char* saveDirPath, const char* fileName) {
    char buffer_1[MAX_PATH] = "";
    
    assert(saveDirPath != NULL);
    assert(fileName != NULL);
    
    
    char* result = PathCombineA(buffer_1, saveDirPath, fileName);
    if (result == NULL)
        return NULL;
    size_t result_len = strlen(result);
    
    size_t ret_buff_len = result_len + 1;
    char* ret_buff = calloc(ret_buff_len, 1);
    strncpy(ret_buff, result, result_len);
}

static char* EncryptString(const char* text, size_t* const encrypted_txt_cap_ret)
{
    size_t text_len = strlen(text);
    size_t text_with_prefix_len = sizeof(uint32_t) + text_len;

    // Round up to multiple of AES block length (16)
    size_t encrypted_txt_cap =
       ((text_with_prefix_len + AES_BLOCKLEN - 1) / AES_BLOCKLEN) * AES_BLOCKLEN;

     char* data = calloc(encrypted_txt_cap, 1);

     // Store big-endian length prefix
     uint32_t write_len = htonl((uint32_t)text_len);
     memcpy(data, &write_len, sizeof(write_len));
     memcpy(data + sizeof(uint32_t), text, text_len);

     // Encrypt the full padded buffer
     AES_init_ctx_iv(&encryption_ctx, key, iv); // important!
     AES_CBC_encrypt_buffer(&encryption_ctx, data, encrypted_txt_cap);
     
     if (encrypted_txt_cap_ret != NULL)
        *encrypted_txt_cap_ret = encrypted_txt_cap; 
     return data;
}

static char* DecryptString(char* data, const size_t encrypted_len) {
    assert(data != NULL);
    
    if(encrypted_len <= sizeof(uint32_t))
    {
        return NULL;
    }
    
    AES_init_ctx_iv(&encryption_ctx, key, iv);
    AES_CBC_decrypt_buffer(&encryption_ctx, data, encrypted_len);
    //string is prefixed with big endian 32 bit length
    uint32_t read_len;
    memcpy(&read_len, data, sizeof(read_len));  // Safe: no unaligned access
    read_len = ntohl(read_len); 
    if (read_len + sizeof(uint32_t) > encrypted_len)
    {
        return NULL;
    }
    data[sizeof(uint32_t) + read_len] = '\0';
        
    size_t text_size = read_len + 1;
    char* text = calloc(text_size, 1);
    strncpy(text, data + sizeof(uint32_t), read_len);
        
    return text;
}

static char* ReadFileAll(const char* filePath, size_t* fileLen)
{
    FILE *f = fopen(filePath, "rb");
    if (f == NULL)
    {
        return NULL;
    }
        
    fseek(f, 0, SEEK_END);
    size_t fLen = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char* data = calloc(fileLen, 1);
    if (data == NULL)
    {
        fclose(f);
        return NULL;
    }
    
    size_t r1 = fread(data, 1, fLen, f); // TODO Loop to ensure whole file read use feof and ferror to determine which one if returns 0
    fclose(f);
    
    if (fileLen != NULL)
        *fileLen = fLen;
    
    return data;
}

static int WriteFileAll(const char* filePath, char* data, size_t dataLen)
{
    assert(filePath != NULL);
    assert(data != NULL);
    
    FILE *f = fopen(filePath, "wb");
    if (f == NULL)
    {
        fprintf(stderr, "Failed to save file!\n");
        return 1;
    }
    
    fwrite(data, 1, encrypted_txt_cap, f); // TODO loop
    fflush(f);
    fclose(f);
    
    return 0;
}

int EncryptAndSaveFile(const char* saveDirPath, const char* fileName, const char* text) {
    
    assert(saveDirPath != NULL);
    assert(fileName != NULL);
    assert(text != NULL);
    
    char* filePath = JonPath(saveDirPath, fileName);
    assert(filePath != NULL);
    
    size_t encrypted_txt_cap = 0;
    char* data = EncryptString(text, &encrypted_txt_cap);
    if (data == NULL)
    {
        fprintf(stderr, "Failed to save file!\n");
        free(filePath);
        return 1;
    }
    
     if (WriteFileAll(filePath, data, size_t dataLen) != 0)
     {
         fprintf(stderr, "Failed to save file!\n");
         free(filePath);
         free(data);
         return 1
     }
    free(filePath);
    free(data);
    printf("Saved text (encrypted)\n");
}

char* ReadFileAndDecrypt(const char* loadDirPath, const char* fileName) {
    
    assert(loadDirPath != NULL);
    assert(fileName != NULL);
    
    char* filePath = JonPath(loadDirPath, fileName);
    assert(filePath != NULL);
    
    //
    size_t encrypted_len = 0;
    char* data = ReadFileAll(filePath, &encrypted_len);
    if (data == NULL)
    {
       fprintf(stderr, "Failed to read file!\n");
       free(filePath);
       return NULL;
    }
    
    free(filePath);
    
    if(encrypted_len <= sizeof(uint32_t))
    {
        free(data);
        return NULL;
    }
    
    char* text = DecryptString(data, encrypted_len);
    if (text == NULL)
        return NULL;
    free(data);
    // '\0' terminate a string
    text = realloc(text, encrypted_len + 1);
    if (text == NULL)
        return NULL;
        text[encrypted_len] = '\0';
    
    printf("Read text (encrypted)\n");
    
    return text;
}

static int DeriveAESKeyFromPassword(const char *password, char aesKey[AES_KEYLEN])
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    int ok = 0;

    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
        {
            CryptHashData(hHash, (BYTE *)password, (DWORD)strlen(password), 0);
            DWORD hashLen = AES_KEYLEN;
            if (CryptGetHashParam(hHash, HP_HASHVAL, aesKey, &hashLen, 0))
                ok = 1;
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    return ok;
}

int IsPasswordIsSetSplitPath(const char* checkDirPath, const char* checkFileName)
{
    assert(checkDirPath != NULL);
    assert(checkFileName != NULL);
    
    char* filePath = JonPath(checkDirPath, checkFileName);
    
    int ret = IsPasswordIsSet(filePath);
    free(filePath);
    return 0;
}

int IsPasswordIsSet(const char* checkFilePath)
{
    assert(checkFilePath != NULL);
     
    if (access(checkFilePath, F_OK) == 0)
    {
        return 1;
    }
    return 0;
}

int CheckPasswordAndDeriveAesKey(const char *password, const char* checkDirPath, const char* checkFileName)
{
    assert(password != NULL);
    assert(checkDirPath != NULL);
    assert(checkFileName != NULL);
    
    char* filePath = JonPath(checkDirPath, checkFileName);

    int ok = DeriveAESKeyFromPassword(password, key);
    if (!ok)
    {
         free(filePath);
         return 0;
    }   
    char keyHash[AES_KEYLEN] = "";
    ok = DeriveAESKeyFromPassword(key, keyHash);
    if (!ok)
    {
        free(filePath);
        return 0;
    } 


    if (IsPasswordIsSet(filePath))
    {
        size_t checkFileLen = 0;
        char* checkFileContent = ReadFileAll(filePath, checkFileLen);
        if (checkFileContent == NULL)
        {
            free(filePath);
            return 0;
            
        }
        free(filePath);
        // TODO add salt to keyHashFile
        if (checkFileLen != AES_KEYLEN)
        {
            return 0;
            free(checkFileContent);
        }
        if (memcmp(keyHash, ) != 0)
        {
            free(checkFileContent);
            return 0;
        }
        free(checkFileContent);
        return 1;
    }
    
    // TODO add salt to keyHashFile
    if (WriteFileAll(const char* filePath, char* data, size_t dataLen) != 0)
    {
        free(filePath);
        return 0;
    }
    free(filePath);
}
