#include <iostream>
#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <stdint.h>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include "common.h"
#include "protocol.h"
#include <sstream>
#include <iomanip>
using namespace std;

/* logging mechanism */
static const char *level_colors[] = {
    "\033[36m", // DEBUG - Cyan
    "\033[32m", // INFO - Green
    "\033[33m", // WARN - Yellow
    "\033[31m"  // ERROR - Red
};
static const char *level_names[] = {
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR"
};

#define COLOR_RESET "\033[0m"

/* logging function */
void LOG(logLevel level, const char *format, ...)
{
    // TODO: fix encoding (strings passed as argument get printed with the wrong encoding)
    // for now we pass a cstring everytime (convert to cstring with string.c_str()
    va_list args;
    va_start(args, format);
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
    printf("%s[%s] [%s]%s ", level_colors[level], buf, level_names[level], COLOR_RESET);
    vprintf(format, args);
    printf("\n");
    va_end(args);
}

/* retrieve private key from PEM file
 *
 * optional passphrase argument */
void readPEMPrivateKey(string filename, EVP_PKEY **privkey, string passphrase)
{
    FILE *file = fopen(filename.c_str(), "r");
    if (!file)
        error("Failed to open PEM file");

    *privkey = PEM_read_PrivateKey(file, NULL, NULL, passphrase.empty() ? NULL : (void *)passphrase.c_str());

    fclose(file);

    if (!*privkey)
        error("Failed to read private key from PEM file");

    return;
}

/* retrieve public key from PEM file
 *
 * optional passphrase argument */
void readPEMPublicKey(string filename, EVP_PKEY **pubkey)
{
    FILE *file = fopen(filename.c_str(), "r");
    if (!file)
        error("Failed to open PEM file");

    *pubkey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    fclose(file);

    if (!*pubkey)
        error("Failed to read public key from PEM file");

    return;
}


/* generate ephemeral DH key pair: (a,g^a)
 *
 * serialize and export pubkey for sending (g^a) */
void DH_keygen(EVP_PKEY *&keypair, byte_vec &public_msg)
{
    keypair = nullptr;
    EVP_PKEY *dh_params = nullptr;

    /* parameter generation for FFDHE-2048 */
    EVP_PKEY_CTX *param_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr);
    if (!param_ctx) error("Failed to create DH param context");

    if (EVP_PKEY_paramgen_init(param_ctx) <= 0)
        error("Failed to initialize DH paramgen");

    if (EVP_PKEY_CTX_set_dh_nid(param_ctx, NID_ffdhe2048) <= 0)
        error("Failed to set DH params to ffdhe2048");

    if (EVP_PKEY_paramgen(param_ctx, &dh_params) <= 0)
        error("Failed to generate DH parameters");

    EVP_PKEY_CTX_free(param_ctx); param_ctx = nullptr;

    /* key generation */
    EVP_PKEY_CTX *key_ctx = EVP_PKEY_CTX_new(dh_params, nullptr);
    EVP_PKEY_free(dh_params); dh_params = nullptr;
    if (!key_ctx) error("Failed to create DH key context");

    if (EVP_PKEY_keygen_init(key_ctx) <= 0)
        error("Failed to initialize DH keygen");

    if (EVP_PKEY_keygen(key_ctx, &keypair) <= 0)
        error("Failed to generate DH keypair");

    EVP_PKEY_CTX_free(key_ctx); key_ctx = nullptr;

    // ---- Export public key (SubjectPublicKeyInfo, DER)
    unsigned char *pubkey_buf = nullptr;
    int pubkey_len = i2d_PUBKEY(keypair, &pubkey_buf);
    if (pubkey_len <= 0)
        error("Failed to encode DH public key");

    public_msg.assign(pubkey_buf, pubkey_buf + pubkey_len);
    OPENSSL_free(pubkey_buf);
}

// assumes: using byte_vec = std::vector<unsigned char>;
// requires: <openssl/evp.h>, <openssl/crypto.h>, <cstring>, <vector>

bool derive_session_secrets(EVP_PKEY *my_keypair,
                            EVP_PKEY *peer_pubkey,
                            const byte_vec &salt,            // MUST match on both ends
                            byte_vec &k_enc_c2s,             // AES-GCM key (e.g., 32 bytes)
                            byte_vec &k_enc_s2c,             // AES-GCM key (e.g., 32 bytes)
                            byte_vec &k_mac_c2s,             // HMAC key (e.g., 32 bytes)
                            byte_vec &k_mac_s2c,             // HMAC key (e.g., 32 bytes)
                            size_t aes_key_len,         // 16 for AES-128-GCM, 32 for AES-256-GCM
                            size_t mac_key_len)         // 32 for HMAC-SHA256
{
    if (!my_keypair || !peer_pubkey) error("Null key(s) supplied");

    // --- 1) Derive the raw DH shared secret Z
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(my_keypair, nullptr);
    if (!ctx) error("Failed to create EVP_PKEY_CTX");

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, peer_pubkey) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        error("EVP_PKEY_derive init/set_peer failed");
    }

    size_t z_len = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &z_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        error("EVP_PKEY_derive (length) failed");
    }

    byte_vec Z(z_len);
    if (EVP_PKEY_derive(ctx, Z.data(), &z_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        error("EVP_PKEY_derive (compute) failed");
    }
    Z.resize(z_len);
    EVP_PKEY_CTX_free(ctx);

    /* function to extract a key from shared secret */
    auto hkdf_expand = [&](const char *label, size_t out_len, byte_vec &out) {
        EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        if (!kctx) error("Failed to create HKDF context");

        bool ok = EVP_PKEY_derive_init(kctx) > 0
               && EVP_PKEY_CTX_set_hkdf_mode(kctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) > 0
               && EVP_PKEY_CTX_set_hkdf_md(kctx, EVP_sha256()) > 0
               && EVP_PKEY_CTX_set1_hkdf_salt(kctx,
                      salt.empty() ? nullptr : salt.data(),
                      static_cast<int>(salt.size())) > 0
               && EVP_PKEY_CTX_set1_hkdf_key(kctx, Z.data(), static_cast<int>(Z.size())) > 0
               && EVP_PKEY_CTX_add1_hkdf_info(
                      kctx,
                      reinterpret_cast<const unsigned char*>(label),
                      static_cast<int>(std::strlen(label))) > 0;

        out.assign(out_len, 0);
        size_t L = out_len;
        ok = ok && EVP_PKEY_derive(kctx, out.data(), &L) > 0 && L == out_len;

        EVP_PKEY_CTX_free(kctx);
        if (!ok) error("HKDF derive failed");
    };

    /* generate 4 keys from shared secret
     * 1. AES client to server
     * 2. AES server to client
     * 3. MAC client to server
     * 4. MAC server to client */
    hkdf_expand("ffdhe2048 aes-gcm key c2s", aes_key_len, k_enc_c2s);
    hkdf_expand("ffdhe2048 aes-gcm key s2c", aes_key_len, k_enc_s2c);
    hkdf_expand("ffdhe2048 hmac key c2s",    mac_key_len, k_mac_c2s);
    hkdf_expand("ffdhe2048 hmac key s2c",    mac_key_len, k_mac_s2c);

    /* zero the shared secret */
    OPENSSL_cleanse(Z.data(), Z.size());

    return true;
}


void 
signRsaSha256(byte_vec &signature, const byte_vec &data, EVP_PKEY *privkey)
{
    // Create the context for signing
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, privkey) <= 0)
    {
        EVP_MD_CTX_free(ctx);
        error("EVP_DigestSignInit failed");
    }

    if (EVP_DigestSignUpdate(ctx, data.data(), data.size()) <= 0)
    {
        EVP_MD_CTX_free(ctx);
        error("EVP_DigestSignUpdate failed");
    }

    // Get signature length
    size_t sig_len = 0;
    if (EVP_DigestSignFinal(ctx, nullptr, &sig_len) <= 0)
    {
        EVP_MD_CTX_free(ctx);
        error("EVP_DigestSignFinal (get length) failed");
    }

    signature.resize(sig_len);

    // Get the signature
    if (EVP_DigestSignFinal(ctx, signature.data(), &sig_len) <= 0)
    {
        EVP_MD_CTX_free(ctx);
        error("EVP_DigestSignFinal failed");
    }

    signature.resize(sig_len);

    EVP_MD_CTX_free(ctx);

    return;
}

bool 
verifyRsaSha256(const byte_vec &data, const byte_vec &signature, EVP_PKEY *pubkey)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        error("Failed to create EVP_MD_CTX for verification");

    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pubkey) <= 0)
    {
        EVP_MD_CTX_free(ctx);
        error("EVP_DigestVerifyInit failed");
    }

    if (EVP_DigestVerifyUpdate(ctx, data.data(), data.size()) <= 0)
    {
        EVP_MD_CTX_free(ctx);
        error("EVP_DigestVerifyUpdate failed");
    }

    int ret = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
    EVP_MD_CTX_free(ctx);

    if (ret == 1)
    {
        return true; // Signature is valid
    }
    else if (ret == 0)
    {
        return false; // Signature is invalid
    }
    else
        error("EVP_DigestVerifyFinal failed");

    return false;
}

/* AES-256-GCM encryption */
void 
aes256gcm_encrypt(const byte_vec &plaintext,
                  const byte_vec &key,
                  byte_vec &iv,
                  byte_vec &ciphertext,
                  byte_vec &tag)
{
    if (key.size() != 32)
        error("Key must be 32 bytes for AES-256-GCM");

    // Generate random 12-byte IV if iv is empty
    if (iv.empty())
    {
        iv.resize(12);
        if (!RAND_bytes(iv.data(), (int)iv.size()))
            error("Failed to generate IV");
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        error("Failed to create EVP_CIPHER_CTX");

    if (EVP_EncryptInit(ctx, EVP_aes_256_gcm(), key.data(), iv.data()) != 1)
        error("EVP_EncryptInit failed");

    int len = 0;
    ciphertext.resize(plaintext.size());

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1)
        error("EVP_EncryptUpdate failed");

    int ciphertext_len = len;

    if (EVP_EncryptFinal(ctx, ciphertext.data() + len, &len) != 1)
        error("EVP_EncryptFinal failed");

    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    tag.resize(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1)
        error("EVP_CIPHER_CTX_ctrl get tag failed");

    EVP_CIPHER_CTX_free(ctx);
}

/* AES-256-GCM decryption */
void 
aes256gcm_decrypt(const byte_vec &ciphertext,
                  const byte_vec &key,
                  const byte_vec &iv,
                  const byte_vec &tag,
                  byte_vec &plaintext)
{
    if (key.size() != 32)
        error("Key must be 32 bytes for AES-256-GCM");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        error("Failed to create EVP_CIPHER_CTX");

    if (EVP_DecryptInit(ctx, EVP_aes_256_gcm(), key.data(), iv.data()) != 1)
        error("EVP_DecryptInit failed");

    int len = 0;
    plaintext.resize(ciphertext.size());

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1)
        error("EVP_DecryptUpdate failed");

    int plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag.size(), (void *)tag.data()) != 1)
        error("EVP_CIPHER_CTX_ctrl set tag failed");

    // Finalize decryption: returns 1 if tag verification succeeds
    int ret = EVP_DecryptFinal(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret != 1)
        error("Decryption failed: tag verification failed");

    plaintext_len += len;
    plaintext.resize(plaintext_len);
}

void 
memzero(string &str)
{
    if (str.empty())
        return;
    fill(str.begin(), str.end(), 0);
}

void 
memzero(byte_vec &data)
{   
    if (data.empty())
        return;
    fill(data.begin(), data.end(), 0);
}

bool
validate_username(const string &username)
{
    if (username.empty() ||
        username.length() > 32 ||
        username.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != string::npos)
    {
        return false;
    }
    
    return true;
}

bool
validate_password(const string &password)
{
    if (password.empty() ||
        password.length() > 32 ||
        password.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_:/\\@#-.,;'?!\"()[]{}&%$*+-<>") != string::npos)
    {
        return false;
    }
    
    return true;
}

/* auxiliary function to print the bytes of a string in hexadecimal format */
std::string toHexString(const std::string& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char c : data) {
        ss << std::setw(2) << static_cast<unsigned int>(c);
    }
    return ss.str();
}

void
byte_to_hex(const byte_vec &in, string &out)
{
    for (uint8_t byte : in) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", static_cast<unsigned char>(byte));
        out += hex;
    }
}

void
hex_to_byte(const string &in, byte_vec &out)
{
    for (size_t i = 0; i < in.length(); i += 2) {
        string byteString = in.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
        out.push_back(byte);
    }
}

