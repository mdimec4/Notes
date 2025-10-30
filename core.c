// core.c - SecureNotes core helpers (AES file encrypt/decrypt + verifier using libsodium Argon2id)
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shlwapi.h>
#include <io.h>
#define F_OK 0
#define access _access
#else
#include <arpa/inet.h> // for htonl/ntohl on non-windows (if ever)
#endif

#include <sodium.h> // libsodium

#include "aes.h"

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

// Globals used by AES routines (from your original PoC)
unsigned char key[AES_KEYLEN] = {0}; // AES_KEYLEN expected to be 32

struct AES_ctx encryption_ctx;

// Verifier file format (vault file) - versioned
// Layout (binary):
// 0..3   : "SNV1" magic (4 bytes)
// 4      : salt_len (1 byte)           (we use 16)
// 5..12  : opslimit (8 bytes, uint64_t little-endian)
//13..20  : memlimit (8 bytes, uint64_t little-endian)
//21..(21+salt_len-1) : salt (salt_len bytes)
//... following: verifier (32 bytes - HMAC-SHA256 result)
// This layout is purposely simple and versioned so we can upgrade later.

static const char VER_MAGIC[4] = { 'S','N','V','1' };
static const size_t VERIFIER_LEN = 32;
static const size_t SALT_LEN_DEFAULT = 16;
static const uint64_t OPSLIMIT_DEFAULT = 3;              // Argon2 ops (time) - tune as desired
static const uint64_t MEMLIMIT_DEFAULT = 64ULL * 1024 * 1024; // 64 MiB

int Init(void)
{
    return sodium_init();
}

// Utility: combine path (Windows PathCombineA). Returns newly allocated string or NULL.
static char* JonPath(const char* saveDirPath, const char* fileName) {
    assert(saveDirPath != NULL);
    assert(fileName != NULL);

    char buffer_1[MAX_PATH] = "";
#ifdef _WIN32
    char* result = PathCombineA(buffer_1, saveDirPath, fileName);
    if (result == NULL) return NULL;
    size_t result_len = strlen(result);
#else
    // non-windows fallback
    int needed = snprintf(buffer_1, sizeof(buffer_1), "%s/%s", saveDirPath, fileName);
    if (needed < 0 || (size_t)needed >= sizeof(buffer_1)) return NULL;
    size_t result_len = (size_t)needed;
#endif

    char* ret_buff = calloc(result_len + 1, 1);
    if (!ret_buff) return NULL;
    memcpy(ret_buff, buffer_1, result_len);
    return ret_buff;
}

// Read entire file into heap buffer. On success returns pointer (must free) and sets *fileLen.
// On failure returns NULL and *fileLen is undefined.
static char* ReadFileAll(const char* filePath, size_t* fileLen) {
    if (!filePath) return NULL;
    FILE *f = fopen(filePath, "rb");
    if (f == NULL) return NULL;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long ft = ftell(f);
    if (ft < 0) { fclose(f); return NULL; }
    size_t fLen = (size_t)ft;
    rewind(f);

    char* data = calloc(fLen + 1, 1); // +1 to allow null-termination if needed
    if (data == NULL) { fclose(f); return NULL; }

    size_t read = 0;
    while (read < fLen) {
        size_t r = fread(data + read, 1, fLen - read, f);
        if (r == 0) {
            if (feof(f)) break;
            if (ferror(f)) { free(data); fclose(f); return NULL; }
        }
        read += r;
    }
    fclose(f);
    if (fileLen) *fileLen = read;
    return data;
}

// Write dataLen bytes to filePath, returns 0 on success, non-zero on error.
static int WriteFileAll(const char* filePath, const char* data, size_t dataLen) {
    if (!filePath || !data) return 1;
    FILE *f = fopen(filePath, "wb");
    if (f == NULL) return 1;

    size_t written = 0;
    while (written < dataLen) {
        size_t w = fwrite(data + written, 1, dataLen - written, f);
        if (w == 0) {
            if (ferror(f)) { fclose(f); return 1; }
        }
        written += w;
    }
    fflush(f);
    fclose(f);
    return 0;
}

static int GenerateRandomBytes(unsigned char *buffer, size_t len) {
    randombytes_buf(buffer, len);
    return 1;
}

static int IsKeyLoaded(void)
{
    static const unsigned char zero_key[AES_KEYLEN] = {0};
    return sodium_memcmp(key, zero_key, AES_KEYLEN) != 0;
}

int EncryptAndSaveFile(const char* saveDirPath, const char* fileName, const char* text) {
    assert(saveDirPath && fileName && text);
    
    if (!IsKeyLoaded()) {
        fprintf(stderr, "Error: no valid AES key loaded. Please log in first.\n");
        return 0; // or NULL for the decrypt function
    }

    char* filePath = JonPath(saveDirPath, fileName);
    assert(filePath);

    size_t text_len = strlen(text);
    size_t total_len = sizeof(uint32_t) + text_len;
    size_t padded_len = ((total_len + AES_BLOCKLEN - 1) / AES_BLOCKLEN) * AES_BLOCKLEN;

    // Allocate buffers
    unsigned char iv[AES_BLOCKLEN];
    if (!GenerateRandomBytes(iv, AES_BLOCKLEN)) {
        fprintf(stderr, "Failed to generate IV!\n");
        free(filePath);
        return 0;
    }

    unsigned char* buffer = calloc(padded_len, 1);
    if (!buffer) {
        free(filePath);
        return 0;
    }

    // Prefix text length (big endian)
    uint32_t be_len = htonl((uint32_t)text_len);
    memcpy(buffer, &be_len, sizeof(be_len));
    memcpy(buffer + sizeof(be_len), text, text_len);

    // Encrypt using the file-specific IV
    AES_init_ctx_iv(&encryption_ctx, key, iv);
    AES_CBC_encrypt_buffer(&encryption_ctx, buffer, padded_len);

    // Write IV + ciphertext to file
    FILE* f = fopen(filePath, "wb");
    if (!f) {
        fprintf(stderr, "Failed to open file for writing\n");
        free(filePath);
        free(buffer);
        return 0;
    }

    fwrite(iv, 1, AES_BLOCKLEN, f);
    fwrite(buffer, 1, padded_len, f);
    fclose(f);

    printf("Saved encrypted file with IV.\n");

    free(filePath);
    free(buffer);
    return 1;
}

char* ReadFileAndDecrypt(const char* loadDirPath, const char* fileName) {
    assert(loadDirPath && fileName);
    
    if (!IsKeyLoaded()) {
        fprintf(stderr, "Error: no valid AES key loaded. Please log in first.\n");
        return 0; // or NULL for the decrypt function
    }

    char* filePath = JonPath(loadDirPath, fileName);
    assert(filePath);

    FILE* f = fopen(filePath, "rb");
    if (!f) {
        fprintf(stderr, "Failed to open file for reading\n");
        free(filePath);
        return NULL;
    }

    unsigned char iv[AES_BLOCKLEN];
    if (fread(iv, 1, AES_BLOCKLEN, f) != AES_BLOCKLEN) {
        fclose(f);
        free(filePath);
        fprintf(stderr, "Failed to read IV\n");
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    size_t total_len = ftell(f);
    fseek(f, AES_BLOCKLEN, SEEK_SET);
    size_t enc_len = total_len - AES_BLOCKLEN;

    unsigned char* enc_data = calloc(enc_len, 1);
    if (!enc_data) {
        fclose(f);
        free(filePath);
        return NULL;
    }

    fread(enc_data, 1, enc_len, f);
    fclose(f);
    free(filePath);

    // Decrypt
    AES_init_ctx_iv(&encryption_ctx, key, iv);
    AES_CBC_decrypt_buffer(&encryption_ctx, enc_data, enc_len);

    // Extract plaintext
    uint32_t be_len;
    memcpy(&be_len, enc_data, sizeof(be_len));
    uint32_t text_len = ntohl(be_len);

    if (text_len > enc_len - sizeof(be_len)) {
        free(enc_data);
        fprintf(stderr, "Corrupted file (length mismatch)\n");
        return NULL;
    }

    char* out = calloc(text_len + 1, 1);
    memcpy(out, enc_data + sizeof(be_len), text_len);
    free(enc_data);

    return out;
}

// Create a vault (verifier) file at checkFilePath using password.
// Returns 0 on success, non-zero on error.
static int CreateVerifierFile(const char* checkFilePath, const char* password) {
    if (!checkFilePath || !password) return 1;
    if (sodium_init() < 0) return 1;

    unsigned char salt[SALT_LEN_DEFAULT];
    randombytes_buf(salt, SALT_LEN_DEFAULT);

    unsigned char derived_key[AES_KEYLEN];
    if (crypto_pwhash(derived_key, AES_KEYLEN,
                      password, strlen(password),
                      salt,
                      (size_t)OPSLIMIT_DEFAULT,
                      (size_t)MEMLIMIT_DEFAULT,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return 1; // out of memory / too slow
    }

    // verifier = HMAC-SHA256(derived_key, "SecureNotes v1 verifier")
    const char *const_str = "SecureNotes v1 verifier";
    unsigned char verifier[VERIFIER_LEN];
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, derived_key, AES_KEYLEN);
    crypto_auth_hmacsha256_update(&st, (const unsigned char*)const_str, strlen(const_str));
    crypto_auth_hmacsha256_final(&st, verifier);

    // Build file buffer
    size_t buf_size = 4 + 1 + 8 + 8 + SALT_LEN_DEFAULT + VERIFIER_LEN;
    unsigned char* buf = calloc(1, buf_size);
    if (!buf) { sodium_memzero(derived_key, AES_KEYLEN); return 1; }

    size_t pos = 0;
    memcpy(buf + pos, VER_MAGIC, 4); pos += 4;
    buf[pos++] = (unsigned char)SALT_LEN_DEFAULT;
    uint64_t ops_le = OPSLIMIT_DEFAULT;
    uint64_t mem_le = MEMLIMIT_DEFAULT;
    // store in little endian for simplicity
    memcpy(buf + pos, &ops_le, sizeof(ops_le)); pos += sizeof(ops_le);
    memcpy(buf + pos, &mem_le, sizeof(mem_le)); pos += sizeof(mem_le);
    memcpy(buf + pos, salt, SALT_LEN_DEFAULT); pos += SALT_LEN_DEFAULT;
    memcpy(buf + pos, verifier, VERIFIER_LEN); pos += VERIFIER_LEN;

    int rc = WriteFileAll(checkFilePath, (char*)buf, pos);

    sodium_memzero(derived_key, AES_KEYLEN);
    sodium_memzero(verifier, VERIFIER_LEN);
    free(buf);
    return rc;
}

// Securely wipes in-memory AES key and any derived secrets.
// Call this when the user logs out.
void Logout(void)
{
    // Overwrite the global AES key with zeros.
    sodium_memzero(key, AES_KEYLEN);

    // Reinitialize the AES context with zeroed key and IV to prevent accidental reuse.
    unsigned char zero_iv[AES_BLOCKLEN] = {0};
    AES_init_ctx_iv(&encryption_ctx, key, zero_iv);

    printf("User logged out. AES key securely cleared.\n");
}

// Check verifier file and if ok, fill global 'key' with derived AES key and return 1.
// Returns 0 on wrong password or error.
int CheckPasswordAndDeriveAesKey(const char *password, const char* checkDirPath, const char* checkFileName)
{
    if (!password || !checkDirPath || !checkFileName) {
        Logout();
        return 0;
    }

    char* filePath = JonPath(checkDirPath, checkFileName);
    if (!filePath) {
        Logout();
        return 0;
    }

    // First-run: create verifier if it does not exist
    if (access(filePath, F_OK) != 0) {
        if (CreateVerifierFile(filePath, password) != 0) {
            free(filePath);
            Logout();
            return 0;
        }
    }

    // Read verifier file
    size_t fileLen = 0;
    char* fileBuf = ReadFileAll(filePath, &fileLen);
    free(filePath);
    if (!fileBuf) {
        Logout();
        return 0;
    }

    // Basic validation
    size_t pos = 0;
    if (fileLen < 4 + 1 + 8 + 8 + 1 + VERIFIER_LEN || memcmp(fileBuf + pos, VER_MAGIC, 4) != 0) {
        free(fileBuf);
        Logout();
        return 0;
    }
    pos += 4;

    unsigned char salt_len = (unsigned char)fileBuf[pos++];
    if (salt_len < 8 || salt_len > 64 || fileLen < 4 + 1 + 8 + 8 + salt_len + VERIFIER_LEN) {
        free(fileBuf);
        Logout();
        return 0;
    }

    uint64_t ops_le = 0, mem_le = 0;
    memcpy(&ops_le, fileBuf + pos, sizeof(ops_le)); pos += sizeof(ops_le);
    memcpy(&mem_le, fileBuf + pos, sizeof(mem_le)); pos += sizeof(mem_le);

    unsigned char salt[64];
    memcpy(salt, fileBuf + pos, salt_len); pos += salt_len;

    unsigned char stored_verifier[VERIFIER_LEN];
    memcpy(stored_verifier, fileBuf + pos, VERIFIER_LEN);

    // Derive key from password
    unsigned char derived_key[AES_KEYLEN];
    if (crypto_pwhash(derived_key, AES_KEYLEN,
                      password, strlen(password),
                      salt,
                      (size_t)ops_le,
                      (size_t)mem_le,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        free(fileBuf);
        Logout();
        return 0;
    }

    // Compute verifier and compare
    const char *const_str = "SecureNotes v1 verifier";
    unsigned char computed_verifier[VERIFIER_LEN];
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, derived_key, AES_KEYLEN);
    crypto_auth_hmacsha256_update(&st, (const unsigned char*)const_str, strlen(const_str));
    crypto_auth_hmacsha256_final(&st, computed_verifier);

    int ok = (sodium_memcmp(computed_verifier, stored_verifier, VERIFIER_LEN) == 0);
    if (ok) {
        memcpy(key, derived_key, AES_KEYLEN);
    } else {
        Logout();
    }

    // Cleanup
    sodium_memzero(derived_key, AES_KEYLEN);
    sodium_memzero(computed_verifier, VERIFIER_LEN);
    sodium_memzero(stored_verifier, VERIFIER_LEN);
    free(fileBuf);

    return ok;
}



// Check if password verifier file exists (split path convenience)
int IsPasswordIsSetSplitPath(const char* checkDirPath, const char* checkFileName) {
    if (!checkDirPath || !checkFileName) return 0;
    char* filePath = JonPath(checkDirPath, checkFileName);
    if (!filePath) return 0;
    int ret = (access(filePath, F_OK) == 0) ? 1 : 0;
    free(filePath);
    return ret;
}

// Check by full path whether password is set
int IsPasswordIsSet(const char* checkFilePath) {
    if (!checkFilePath) return 0;
    return (access(checkFilePath, F_OK) == 0) ? 1 : 0;
}

