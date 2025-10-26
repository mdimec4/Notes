#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

//#define _WINSOCKAPI_   // Prevent conflicts with sys/select.h
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shlwapi.h>

#include "aes.h"

unsigned char key[AES_KEYLEN + 1] = "01234567890123456789012345678901"; // 32 bytes
unsigned char iv[AES_BLOCKLEN +1] = "0123456789012345";                    // 16 bytes

struct AES_ctx encryption_ctx;

char* JonPath(char* saveDirPath, char* fileName) {
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

char* EncryptString(char* text, size_t* encrypted_txt_cap_ret)
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

void EncryptAndSaveFile(char* saveDirPath, char* fileName, char* text) {
    
    assert(saveDirPath != NULL);
    assert(fileName != NULL);
    
    char* filePath = JonPath(saveDirPath, fileName);
    assert(filePath != NULL);
    
    FILE *f = fopen(filePath, "wb");
    free(filePath);

    if (f) {
        size_t encrypted_txt_cap = 0;
        char* data = EncryptString(text, &encrypted_txt_cap);

        fwrite(data, 1, encrypted_txt_cap, f);

        free(data);
        fflush(f);
        fclose(f);
        printf("Saved text to notes.txt (encrypted)\n");
    } else {
        fprintf(stderr, "Failed to save file!\n");
    }
}

char* ReadFileAndDecrypt(char* loadDirPath, char* fileName) {
    
    assert(loadDirPath != NULL);
    assert(fileName != NULL);
    
    char* filePath = JonPath(loadDirPath, fileName);
    assert(filePath != NULL);
    
    FILE *f = fopen(filePath, "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        size_t encrypted_len = ftell(f);
        fseek(f, 0, SEEK_SET);
        
        if(encrypted_len <= sizeof(uint32_t))
        {
            fclose(f);
            return NULL;
        }
        char* data = calloc(encrypted_len + 1, 1);

        size_t r1 = fread(data, 1, encrypted_len, f); 
        fclose(f);

        AES_init_ctx_iv(&encryption_ctx, key, iv);
        AES_CBC_decrypt_buffer(&encryption_ctx, data, encrypted_len);
        //string is prefixed with big endian 32 bit length
        
        uint32_t read_len;
        memcpy(&read_len, data, sizeof(read_len));  // Safe: no unaligned access
        read_len = ntohl(read_len); 
        if (read_len + sizeof(uint32_t) > encrypted_len)
        {
            free(data);
            return NULL;
        }
        data[sizeof(uint32_t) + read_len] = '\0';
        
        size_t text_size = read_len + 1;
        char* text = calloc(text_size, 1);
        strncpy(text, data + sizeof(uint32_t), read_len);

        free(data);
        printf("Read text from notes.txt (unencrypted for now)\n");
        return text;
    } 
    
    fprintf(stderr, "Failed to read file!\n");
    return NULL;
}