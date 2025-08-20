#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../common/common.h"
#include "../common/protocol.h"
#include "../common/constant.h"
using namespace std;

byte_vec k_enc_c2s(32);
byte_vec k_enc_s2c(32);
byte_vec k_mac_c2s(32);
byte_vec k_mac_s2c(32);
uint64_t counter = 0;
int sockfd;


int connect_to_server(const string &host, uint16_t port)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        error("socket returned < 0");
    }

    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &serv_addr.sin_addr) <= 0)
    {
        error("intet_pton failed");
    }

    if (connect(sockfd, (sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        error("connect failed");
    }

    LOG(INFO, "Connected to server at %s:%d", host.c_str(), port);
    return sockfd;
}


void client_init_connection()
{
    sockfd = connect_to_server("127.0.0.1", 4242);

    string path_to_public_key = DATA_PATH + "/client/pub_server.pem";

    EVP_PKEY *server_rsa_pub = nullptr;
    readPEMPublicKey(path_to_public_key, &server_rsa_pub);

    init_secure_channel(sockfd,
                        server_rsa_pub,
                        k_enc_c2s,
                        k_enc_s2c,
                        k_mac_c2s,
                        k_mac_s2c
                        );
}

void close_connection()
{
    if (sockfd >= 0)
    {
        close(sockfd);
        sockfd = -1;
    }

    memzero(k_enc_c2s);
    memzero(k_enc_s2c);
    memzero(k_mac_c2s);
    memzero(k_mac_s2c);
}

int main()
{
    try 
    {
        client_init_connection();

        /* test 0: send with payload */
        uint64_t counter = 0;
        send_message("Hello server!", sockfd, k_enc_c2s, counter, CREATE_KEYS);

        /* test 1: recv back same payload */
        byte_vec msg;
        uint8_t type;
        recv_message(msg, sockfd, k_enc_s2c, counter, type);
        std::string msg_str(reinterpret_cast<const char*>(msg.data()), msg.size());
        LOG(DEBUG, "[TEST-1] received message: %s. client: %d, counter: %lu, type: %x",
            msg_str.c_str(), sockfd, counter, type);

        /* test 2: send message with no payload */
        byte_vec empty;
        send_message(empty, sockfd, k_enc_c2s, counter, CREATE_KEYS);

        /* TODO: implement functionalities of DSS */
        // cmd_Login();
        // while(1)
        //     operation();
    }
    catch (const runtime_error &e)
    {
        LOG(ERROR, "Runtime error: %s", e.what());
        close_connection();
    }
    catch (const exception &e)
    {
        LOG(ERROR, "Exception: %s", e.what());
        close_connection();
    }
    catch (...)
    {
        LOG(ERROR, "Unknown error occurred");
        close_connection();
    }

    close_connection();

    return 0;
}

