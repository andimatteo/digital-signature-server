#include "protocol.h"
#include "common.h"
#include "constant.h"
#include "header.h"
using namespace std;

byte_vec iv_enc(4,0);

/* utility function */
static inline 
void be64(uint8_t* out, uint64_t v){
    out[0]=uint8_t(v>>56); out[1]=uint8_t(v>>48); out[2]=uint8_t(v>>40); out[3]=uint8_t(v>>32);
    out[4]=uint8_t(v>>24); out[5]=uint8_t(v>>16); out[6]=uint8_t(v>>8);  out[7]=uint8_t(v);
}


/* function to send and receive all bytes of a message */
static bool 
send_all(int sockfd, const unsigned char *data, size_t len)
{
    LOG(DEBUG, "Sending %zu bytes", len);
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = ::send(sockfd, data + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += size_t(n);
    }
    return true;
}
static bool 
recv_all(int sockfd, unsigned char *data, size_t len)
{
    size_t got = 0;
    while (got < len) {
        ssize_t n = ::recv(sockfd, data + got, len - got, 0);
        if (n <= 0) return false;
        got += size_t(n);
    }
    return true;
}

/* utility send function used during DHKE */
bool 
send_message(int sockfd, const byte_vec &data)
{
    if (data.size() > UINT32_MAX)
        error("Data size exceeds maximum limit");
    uint32_t len = htonl(data.size());
    if (!send_all(sockfd, reinterpret_cast<unsigned char *>(&len), sizeof(len)))
        return false;
    if (!send_all(sockfd, data.data(), data.size()))
        return false;
    return true;
}

/* utility recv function used during DHKE */
bool 
recv_message(int sockfd, byte_vec &out)
{
    uint32_t len_net = 0;
    if (!recv_all(sockfd, reinterpret_cast<unsigned char *>(&len_net), sizeof(len_net)))
        return false;

    uint32_t len = ntohl(len_net);
    if (len > MAX_DOC_SIZE) // Optional: limit to 10 MB
        return false;

    out.resize(len);
    return recv_all(sockfd, out.data(), len);
}


static constexpr size_t PAD_BLOCK = 16;

/*
 * the communication protocol is the following:
 *  1. send header: (encrypt then authenticate)
 *      - 1 type byte
 *      - 8 len byte (len of padded payload)
 *      - 8 IV bytes (++counter)
 *      - then we pad this header (64 bytes)
 *      - then we compute HMAC of the ciphertext (16 bytes)
 *      - and then we send encrypted header and HMAC (64 + 16 bytes)
 *  2. optionally send payload: (encrypt then authenticate)
 *      - payload of variable size
 *      - 8 IV bytes (++counter)
 *      - pad (payload||IV) --> (len)
 *      - encrypt (len)
 *      - compute HMAC of ciphertext (len + 16 bytes)
 *      - send encrypted payload and HMAC (len + 16 bytes)
 * */
static void 
send_secure_record(int sockfd,
                   uint8_t type_byte,
                   const byte_vec &payload,
                   const byte_vec &key,
                   uint64_t &counter)
{
    /* Calculate padded payload length (including IV) */
    uint64_t payload_padded_len = 0;
    if (!payload.empty()) {
        size_t rem = payload.size() % PAD_BLOCK;
        size_t pad = (rem == 0) ? PAD_BLOCK : (PAD_BLOCK - rem);
        payload_padded_len = payload.size() + pad;
    }
    
    /* header plaintext: type + length */
    byte_vec hdr_plain;
    
    /* increment counter */
    ++counter;

    // 1 byte type
    hdr_plain.push_back(type_byte);
    
    // 8 bytes length (of padded payload)
    byte_vec len_bytes(8, 0);
    be64(len_bytes.data(), payload_padded_len);
    hdr_plain.insert(hdr_plain.end(), len_bytes.begin(), len_bytes.end());
    

    /* PKCS#7 padding for header */
    byte_vec hdr_padded = hdr_plain;
    {
        size_t rem = hdr_padded.size() % PAD_BLOCK;
        size_t pad = (rem == 0) ? PAD_BLOCK : (PAD_BLOCK - rem);
        hdr_padded.insert(hdr_padded.end(), pad, (uint8_t)pad);
    }

    /* encrypt header (with padding) */
    byte_vec hdr_ct, hdr_tag;
    byte_vec iv_zero(12, 0);

    /* init IV AES-256-GCM
     * first 4 byte nonce from shared secret 
     * last 8 bytes from counter */
    memcpy(iv_zero.data(), iv_enc.data(), 4);
    memcpy(iv_zero.data() + 4, &counter, sizeof(uint64_t));

    aes256gcm_encrypt(hdr_padded, key, iv_zero, hdr_ct, hdr_tag);
    
    if (hdr_ct.size() != PAD_BLOCK) error("encrypted header length mismatch");
    
    /* send header and tag (fixed 16 + 16 = 32B) */
    if (!send_all(sockfd, hdr_ct.data(),  hdr_ct.size()))  error("send_all header ct failed");
    if (!send_all(sockfd, hdr_tag.data(), hdr_tag.size())) error("send_all header tag failed");
    
    /* the payload is optional */
    if (!payload.empty()) {
        /* prepare payload with IV */
        byte_vec payload_with_iv = payload;
        
        /* increment counter */
        ++counter;

        /* pad (payload||IV) */
        byte_vec padded = payload_with_iv;
        {
            size_t rem = padded.size() % PAD_BLOCK;
            size_t pad = (rem == 0) ? PAD_BLOCK : (PAD_BLOCK - rem);
            padded.insert(padded.end(), pad, (uint8_t)pad);
        }

        /* encrypt payload */
        byte_vec ct, tag;
        byte_vec iv_zero(12, 0);
        
        /* init IV AES-256-GCM
         * first 4 byte nonce from shared secret 
         * last 8 bytes from counter */
        memcpy(iv_zero.data(), iv_enc.data(), 4);
        memcpy(iv_zero.data() + 4, &counter, sizeof(uint64_t));
        aes256gcm_encrypt(padded, key, iv_zero, ct, tag);
        
        /* send payload and tag */
        if (!send_all(sockfd, ct.data(),  ct.size()))  error("send_all payload ct failed");
        if (!send_all(sockfd, tag.data(), tag.size())) error("send_all payload tag failed");
        
        memzero(padded);
    }

    LOG(DEBUG, "Sent message: payload_size=%zu, counter=%llu",
        (payload.empty() ? 0 : payload.size()), (unsigned long long)counter);

    memzero(hdr_padded);
}

/* receive record */
static bool 
recv_secure_record(int sockfd,
                   const byte_vec &key,
                   uint64_t &counter,
                   uint8_t &type_out,
                   byte_vec &payload_out)
{
    /* receive header with padding */
    byte_vec hdr_ct(PAD_BLOCK);
    byte_vec hdr_tag(16);
    if (!recv_all(sockfd, hdr_ct.data(),  hdr_ct.size()))  return false;
    if (!recv_all(sockfd, hdr_tag.data(), hdr_tag.size())) return false;

    /* init IV AES-256-GCM
     * first 4 byte nonce from shared secret 
     * last 8 bytes from counter */
    byte_vec iv_zero(12, 0);
    memcpy(iv_zero.data(), iv_enc.data(), 4);
    memcpy(iv_zero.data() + 4, &++counter, sizeof(uint64_t));
    
    /* decrypt header */
    byte_vec hdr_padded;
    aes256gcm_decrypt(hdr_ct, key, iv_zero, hdr_tag, hdr_padded);

    /* remove padding */
    if (hdr_padded.empty()) error("empty header padded");
    uint8_t hpad = hdr_padded.back();
    if (hpad == 0 || hpad > hdr_padded.size()) error("bad header padding");
    hdr_padded.resize(hdr_padded.size() - hpad);

    // Header should have 1 byte type, 8 bytes length
    if (hdr_padded.size() != 9) error("bad header length after unpad");
    
    // Extract the type byte
    type_out = hdr_padded[0];
    
    // Extract the length (padded payload length)
    uint64_t payload_padded_len = 0;
    for (int i = 0; i < 8; ++i) {
        payload_padded_len = (payload_padded_len << 8) | hdr_padded[i + 1];
    }

    /* if the message has a payload then we receive it */
    if (payload_padded_len > 0) {
        /* receive payload and tag */
        byte_vec ct(payload_padded_len), tag(16);
        if (!recv_all(sockfd, ct.data(),  ct.size()))  return false;
        if (!recv_all(sockfd, tag.data(), tag.size())) return false;

        /* decrypt payload */
        byte_vec iv_zero(12, 0); // Zero IV as counter is in data
        memcpy(iv_zero.data(), iv_enc.data(), 4);
        memcpy(iv_zero.data() + 4, &++counter, sizeof(uint64_t));
        
        byte_vec padded;
        aes256gcm_decrypt(ct, key, iv_zero, tag, padded);

        /* remove padding */
        if (padded.empty()) error("empty payload padded");
        uint8_t pad = padded.back();
        if (pad == 0 || pad > padded.size()) error("bad payload padding");
        padded.resize(padded.size() - pad);

        payload_out.swap(padded);
    }

    return true;
}

void send_message(const string &msg, int sockfd, const byte_vec &key, uint64_t &counter, uint8_t type_byte)
{
    byte_vec msg_bytes(msg.begin(), msg.end());
    send_secure_record(sockfd, type_byte, msg_bytes, key, counter);
    memzero(msg_bytes);
}

void send_message(const byte_vec &msg, int sockfd, const byte_vec &key, uint64_t &counter, uint8_t type_byte)
{
    send_secure_record(sockfd, type_byte, msg, key, counter);
}

bool recv_message(byte_vec &payload_out, int sockfd, const byte_vec &key, uint64_t &counter, uint8_t &type_byte_out)
{
    return recv_secure_record(sockfd, key, counter, type_byte_out, payload_out);
}


#ifdef _SERVER

bool
init_secure_channel(int sockfd,
                    EVP_PKEY *server_rsa_priv,
                    byte_vec &k_enc_c2s,
                    byte_vec &k_enc_s2c,
                    byte_vec &iv_enc_c2s,
                    byte_vec &iv_enc_s2c)
{
    LOG(INFO, "Initializing secure conversation with client");


    /* retrieve client public key (g^a) */
    byte_vec client_pub_dh_msg;
    if (!recv_message(sockfd, client_pub_dh_msg))
        error("Failed to receive client DH public key");
    const unsigned char *pc = client_pub_dh_msg.data();
    EVP_PKEY *client_dh_pubkey = d2i_PUBKEY(nullptr, &pc, (long)client_pub_dh_msg.size());
    if (!client_dh_pubkey)
        error("Failed to parse client DH public key");

    /* generate server private and public key (b,g^b) */
    byte_vec my_pub_dh_msg;
    EVP_PKEY *my_dh_keypair = nullptr;
    DH_keygen(my_dh_keypair,my_pub_dh_msg);

    /* sign g^a || g^b with server RSA private key */
    byte_vec signed_data = client_pub_dh_msg;
    signed_data.insert(signed_data.end(), my_pub_dh_msg.begin(), my_pub_dh_msg.end());
    byte_vec signature;
    signRsaSha256(signature, signed_data, server_rsa_priv);

    
    /* send g^b to the client */
    if (!send_message(sockfd, my_pub_dh_msg)) {
        EVP_PKEY_free(client_dh_pubkey);
        error("Failed to send server DH public key");
    }

    /* send send the signed message <g^a || g^b>_server */
    if (!send_message(sockfd, signature)) {
        EVP_PKEY_free(client_dh_pubkey);
        error("Failed to send server signature");
    }

    /* get session keys from shared secret using HKDF:
     * 1. AES client to server
     * 2. AES server to client
     * 3. MAC client to server 
     * 4. MAC server to client */
    if (!derive_session_secrets(my_dh_keypair, client_dh_pubkey, k_enc_c2s, k_enc_s2c, iv_enc_c2s, iv_enc_s2c))
    {
        EVP_PKEY_free(my_dh_keypair);
        EVP_PKEY_free(client_dh_pubkey);
        error("Shared key derivation failed");
    }

    /* delete server private key (b) */
    EVP_PKEY_free(my_dh_keypair);
    my_dh_keypair = nullptr;


    LOG(INFO,"secure channel created successfully");
        
    EVP_PKEY_free(client_dh_pubkey);
    return true;
}

/* client function implementation
 * compile WITHOUT -D_SERVER */
#else

/* init a secure channel from client's point of view
 * 1) send g^a
 * 2) receive g^b and { <g^a || g^b>_S }_K
 * 3) derive K = g^(ab) and DELETE a, then decrypt and verify signature
 */
bool 
init_secure_channel(int sockfd,
                    EVP_PKEY *server_rsa_pub,
                    byte_vec &k_enc_c2s,
                    byte_vec &k_enc_s2c,
                    byte_vec &iv_enc_c2s,
                    byte_vec &iv_enc_s2c)
{
    LOG(INFO, "Initializing secure conversation with server");

    // 1) Generate client key pair (a, g^a) and send g^a
    byte_vec my_pub_dh_msg;
    EVP_PKEY *my_dh_keypair = nullptr;
    DH_keygen(my_dh_keypair, my_pub_dh_msg);
    if (!send_message(sockfd, my_pub_dh_msg))
        error("Failed to send client DH public key");
    LOG(DEBUG, "Sent client DH public key (%zu bytes)", my_pub_dh_msg.size());

    // 2) Receive g^b (server's DH public)
    byte_vec server_pub_dh_msg;
    if (!recv_message(sockfd, server_pub_dh_msg))
        error("Failed to receive server DH public key");
    LOG(DEBUG, "Received server DH public key (%zu bytes)", server_pub_dh_msg.size());

    // 3) Receive signature over (g^a || g^b)
    byte_vec signature;
    if (!recv_message(sockfd, signature))
        error("Failed to receive server signature");
    LOG(DEBUG, "Received server signature (%zu bytes)", signature.size());

    byte_vec signed_data;
    signed_data.reserve(my_pub_dh_msg.size() + server_pub_dh_msg.size());
    signed_data.insert(signed_data.end(), my_pub_dh_msg.begin(),     my_pub_dh_msg.end());
    signed_data.insert(signed_data.end(), server_pub_dh_msg.begin(), server_pub_dh_msg.end());

    if (!verifyRsaSha256(signed_data, signature, server_rsa_pub)) {
        error("Server signature verification failed");
    }

    // 4) Decode g^b and derive session secrets from DH shared secret K=g^(ab)
    const unsigned char *ps = server_pub_dh_msg.data();
    EVP_PKEY *server_dh_pubkey = d2i_PUBKEY(nullptr, &ps, (long)server_pub_dh_msg.size());
    if (!server_dh_pubkey)
        error("Failed to parse server DH public key");

    if (!derive_session_secrets(my_dh_keypair, server_dh_pubkey,
                                k_enc_c2s, k_enc_s2c, iv_enc_c2s, iv_enc_s2c))
    {
        EVP_PKEY_free(my_dh_keypair);
        EVP_PKEY_free(server_dh_pubkey);
        error("Shared key derivation failed");
    }

    // 5) Delete client private key (a)
    EVP_PKEY_free(my_dh_keypair);
    my_dh_keypair = nullptr;

    LOG(DEBUG, "Server signature verified successfully");
    LOG(INFO, "Secure channel created succefully");

    EVP_PKEY_free(server_dh_pubkey);
    return true;
}


#endif

