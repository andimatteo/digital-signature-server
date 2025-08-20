#ifndef _PROTOCOL
#define _PROTOCOL

#include <sys/socket.h>
#include <netinet/in.h>
#include "common.h"


bool init_secure_channel(int sockfd,
                              EVP_PKEY *server_rsa_priv,
                              byte_vec &k_enc_c2s,
                              byte_vec &k_enc_s2c,
                              byte_vec &k_mac_c2s,
                              byte_vec &k_mac_s2c );


bool recv_message(int sockfd, byte_vec &out);
bool send_message(int sockfd, const byte_vec &data);
void send_message(const string &msg, int sockfd, const byte_vec &key, uint64_t &counter, uint8_t type_byte);
void send_message(const byte_vec &msg, int sockfd, const byte_vec &key, uint64_t &counter, uint8_t type_byte);
bool recv_message(byte_vec &payload_out, int sockfd, const byte_vec &key, uint64_t &counter, uint8_t &type_byte_out);

#endif
