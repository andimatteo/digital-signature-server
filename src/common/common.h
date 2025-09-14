#ifndef _COMMON
#define _COMMON

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <vector>
#include <cstdint>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <vector>
#include <stdexcept>
#include <string>

using namespace std;

typedef enum
{
    DEBUG,
    INFO,
    WARN,
    ERROR
} logLevel;

using byte_vec = vector<uint8_t>;

const string DATA_PATH = "data";

void memzero(string &str);
void memzero(byte_vec &data);
void readPEMPrivateKey(string filename, EVP_PKEY **privkey, string passphrase = "");
void readPEMPublicKey(string filename, EVP_PKEY **pubkey);
void inline error(const char *msg) { throw runtime_error(msg); }
void LOG(logLevel level, const char *format, ...);
void signRsaSha256(byte_vec &signature, const byte_vec &data, EVP_PKEY *privkey);
bool verifyRsaSha256(const byte_vec &data, const byte_vec &signature, EVP_PKEY *pubkey);
void DH_keygen( EVP_PKEY *&keypair, byte_vec &public_msg);
bool derive_session_secrets(EVP_PKEY *my_keypair,
                            EVP_PKEY *peer_pubkey,
                            byte_vec &k_enc_c2s,             // AES-GCM key (e.g., 32 bytes)
                            byte_vec &k_enc_s2c,             // AES-GCM key (e.g., 32 bytes)
                            byte_vec &iv,             // HMAC key (e.g., 32 bytes)
                            byte_vec &iv_s2c,             // HMAC key (e.g., 32 bytes)
                            size_t aes_key_len = 32,         // 16 for AES-128-GCM, 32 for AES-256-GCM
                            size_t mac_key_len = 4);
void aes256gcm_encrypt(const byte_vec &plaintext,
                  const byte_vec &key,
                  byte_vec &iv,
                  byte_vec &ciphertext,
                  byte_vec &tag);
void aes256gcm_decrypt(const byte_vec &ciphertext,
                  const byte_vec &key,
                  const byte_vec &iv,
                  const byte_vec &tag,
                  byte_vec &plaintext);
bool validate_username(const string &username);
bool validate_password(const string &password);
string toHexString(const std::string& data);
void hex_to_byte(const string &in, byte_vec &out);
void byte_to_hex(const byte_vec &in, string &out);

#endif
