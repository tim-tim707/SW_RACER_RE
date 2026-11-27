#include "hash_util.h"

#include <cstdint>

#include <windows.h>
#include <bcrypt.h>

bool sha256_hex(const void *data, size_t size, std::string *out) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        return false;

    uint8_t digest[32] = {};
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = BCRYPT_SUCCESS(BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0));
    if (ok) {
        ok = BCRYPT_SUCCESS(BCryptHashData(hash, (PUCHAR) data, (ULONG) size, 0)) &&
            BCRYPT_SUCCESS(BCryptFinishHash(hash, digest, sizeof(digest), 0));
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (!ok)
        return false;

    static const char HEX[] = "0123456789abcdef";
    out->clear();
    for (uint8_t byte: digest) {
        out->push_back(HEX[byte >> 4]);
        out->push_back(HEX[byte & 0xf]);
    }
    return true;
}
