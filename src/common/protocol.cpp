#include "protocol.h"
#include "common.h"
#include "constant.h"
#include "header.h"
using namespace std;

/*
 * the communication protocol is the following:
 * 1. we send {type || len}_k encrypted header of fixed size (1 + 8) bytes
 * 2. we send {payload || padding}_k encrypted payload of variable size
 *
 * the main interface to send and receive a secure message is the following:
 * send_message(msg, int sockfd, byte_vec key, uint64_t counter)
 * where:
 *  - msg: is the payload to send (can be a string or a byte_vec)
 *  - sockf: is the communication socket
 *  - key: is the symmetric encryption key
 *  - counter: is the sequence number of the message (so that same messages will
 *    have different encodings)
 *
 * both send and receive are structured with the following abstraction layers:
 * 1. a function to send or receive all bytes (e.g. send_all)
 * 2. an encryption function for sending the message
 * 3. a simple interface function for sending data according to the protocol
 * */

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


static constexpr size_t PAD_BLOCK = 64;

/* TODO: modificare le funzioni che vengono chiamate durante lo scambio di dati da client.cpp e server.cpp */
/* NOTE: fare testing delle varie richieste (non viene realmente fatto qualcosa) */

/* function for sending the header + variable size payload */
static void 
send_secure_record(int sockfd,
                   uint8_t type_byte,
                   const byte_vec &payload,
                   const byte_vec &key,
                   uint64_t &counter)
{
    /* header plaintext */
    header hdr{};
    hdr.type   = type_byte;
    hdr.length = static_cast<uint64_t>(payload.size());
    byte_vec hdr_plain = hdr.serialize(); // 9 bytes

    /* PKCS#7 padding for header => 64B */
    byte_vec hdr_padded = hdr_plain;
    {
        size_t rem = hdr_padded.size() % PAD_BLOCK;
        size_t pad = (rem == 0) ? PAD_BLOCK : (PAD_BLOCK - rem);
        hdr_padded.insert(hdr_padded.end(), pad, (uint8_t)pad);
    }

    /* header IV: ++counter */
    byte_vec iv_h(12, 0);
    be64(iv_h.data() + 4, ++counter);

    /* encrypt header (with padding) */
    byte_vec hdr_ct, hdr_tag;
    aes256gcm_encrypt(hdr_padded, key, iv_h, hdr_ct, hdr_tag);
    if (hdr_ct.size() != PAD_BLOCK) error("encrypted header length mismatch");
    
    /* send header and tag (fixed 64 + 16 = 80B) */
    if (!send_all(sockfd, hdr_ct.data(),  hdr_ct.size()))  error("send_all header ct failed");
    if (!send_all(sockfd, hdr_tag.data(), hdr_tag.size())) error("send_all header tag failed");
    
    /* the payload is optional:
     * the other peer knows that no payload will be sent
     * for example createKeys and deleteKeys responses have no payload */
    if (hdr.length) {
        /* payload padding */
        byte_vec padded = payload;
        {
            size_t rem = padded.size() % PAD_BLOCK;
            size_t pad = (rem == 0) ? PAD_BLOCK : (PAD_BLOCK - rem);
            padded.insert(padded.end(), pad, (uint8_t)pad);
        }

        /* payload IV: ++counter */
        byte_vec iv_p(12, 0);
        be64(iv_p.data() + 4, ++counter);

        /* encrypt payload */
        byte_vec ct, tag;
        aes256gcm_encrypt(padded, key, iv_p, ct, tag);
        
        /* send payload and tag (payload_size + 16B) */
        if (!send_all(sockfd, ct.data(),  ct.size()))  error("send_all payload ct failed");
        if (!send_all(sockfd, tag.data(), tag.size())) error("send_all payload tag failed");
        
        memzero(padded);
    }

    LOG(DEBUG, "Sent message: payload_size=%zu, counter=%llu",
        hdr.length, (unsigned long long)counter);

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

    /* IV header: ++counter */
    byte_vec iv_h(12, 0);
    be64(iv_h.data() + 4, ++counter);

    /* decrypt header */
    byte_vec hdr_padded;
    aes256gcm_decrypt(hdr_ct, key, iv_h, hdr_tag, hdr_padded);

    /* remove padding and get 1 + 8 B */
    if (hdr_padded.empty()) error("empty header padded");
    uint8_t hpad = hdr_padded.back();
    if (hpad == 0 || hpad > hdr_padded.size()) error("bad header padding");
    hdr_padded.resize(hdr_padded.size() - hpad);

    if (hdr_padded.size() != 9) error("bad header length after unpad");

    header hdr{};
    if (!header::deserialize(hdr_padded, hdr)) error("header deserialize failed");
    type_out = hdr.type;

    /* if the message has a payload then we receive it */
    if (hdr.length) {
        uint64_t L = hdr.length;
        size_t padded_len = size_t(L % PAD_BLOCK == 0 ? L + PAD_BLOCK : L + (PAD_BLOCK - (L % PAD_BLOCK)));

        /* receive payload and tag */
        byte_vec ct(padded_len), tag(16);
        if (!recv_all(sockfd, ct.data(),  ct.size()))  return false;
        if (!recv_all(sockfd, tag.data(), tag.size())) return false;

        /* payload IV: ++counter */
        byte_vec iv_p(12, 0);
        be64(iv_p.data() + 4, ++counter);

        /* decrypt payload */
        byte_vec padded;
        aes256gcm_decrypt(ct, key, iv_p, tag, padded);

        /* remove padding */
        if (padded.empty()) error("empty payload padded");
        uint8_t pad = padded.back();
        if (pad == 0 || pad > padded.size()) error("bad payload padding");
        // NOTE: we should also check that pad last bytes are equal to pad
        padded.resize(padded.size() - pad);

        if (padded.size() != hdr.length) error("length mismatch after unpad");

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
                    byte_vec &k_mac_c2s,
                    byte_vec &k_mac_s2c)
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

    /* NOTE: salt (opzionale) */
    byte_vec salt;
    // {
    //     static const char lbl[] = "ffdhe2048";
    //     salt.resize(sizeof(lbl) - 1 + client_pub_dh_msg.size() + my_pub_dh_msg.size());
    //     unsigned char *w = salt.data();
    //     std::memcpy(w, lbl, sizeof(lbl) - 1);                  w += sizeof(lbl) - 1;
    //     std::memcpy(w, client_pub_dh_msg.data(), client_pub_dh_msg.size()); w += client_pub_dh_msg.size();
    //     std::memcpy(w, my_pub_dh_msg.data(), my_pub_dh_msg.size());
    // }

    /* get session keys from shared secret using HKDF:
     * 1. AES client to server
     * 2. AES server to client
     * 3. MAC client to server 
     * 4. MAC server to client */
    if (!derive_session_secrets(my_dh_keypair, client_dh_pubkey, salt, k_enc_c2s, k_enc_s2c, k_mac_c2s, k_mac_s2c))
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
                    byte_vec &k_mac_c2s,
                    byte_vec &k_mac_s2c)
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

    // 4) Decode g^b and derive session secrets from DH shared secret K=g^(ab)
    const unsigned char *ps = server_pub_dh_msg.data();
    EVP_PKEY *server_dh_pubkey = d2i_PUBKEY(nullptr, &ps, (long)server_pub_dh_msg.size());
    if (!server_dh_pubkey)
        error("Failed to parse server DH public key");

    // Optional transcript-bound salt (must match server if used)
    byte_vec salt;
    // {
    //     static const char lbl[] = "ffdhe2048";
    //     salt.resize(sizeof(lbl) - 1 + my_pub_dh_msg.size() + server_pub_dh_msg.size());
    //     unsigned char *w = salt.data();
    //     std::memcpy(w, lbl, sizeof(lbl) - 1);                                  w += sizeof(lbl) - 1;
    //     std::memcpy(w, my_pub_dh_msg.data(),      my_pub_dh_msg.size());        w += my_pub_dh_msg.size();
    //     std::memcpy(w, server_pub_dh_msg.data(),  server_pub_dh_msg.size());
    // }

    if (!derive_session_secrets(my_dh_keypair, server_dh_pubkey, salt,
                                k_enc_c2s, k_enc_s2c, k_mac_c2s, k_mac_s2c))
    {
        EVP_PKEY_free(my_dh_keypair);
        EVP_PKEY_free(server_dh_pubkey);
        error("Shared key derivation failed");
    }

    // 5) Delete client private key (a)
    EVP_PKEY_free(my_dh_keypair);
    my_dh_keypair = nullptr;

    // 6) Verify server's signature over (g^a || g^b)
    byte_vec signed_data;
    signed_data.reserve(my_pub_dh_msg.size() + server_pub_dh_msg.size());
    signed_data.insert(signed_data.end(), my_pub_dh_msg.begin(),     my_pub_dh_msg.end());
    signed_data.insert(signed_data.end(), server_pub_dh_msg.begin(), server_pub_dh_msg.end());

    if (!verifyRsaSha256(signed_data, signature, server_rsa_pub)) {
        EVP_PKEY_free(server_dh_pubkey);
        error("Server signature verification failed");
    }
    LOG(DEBUG, "Server signature verified successfully");
    LOG(INFO, "Secure channel created succefully");

    EVP_PKEY_free(server_dh_pubkey);
    return true;
}


#endif

