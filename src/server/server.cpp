#include <iostream>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include "../common/common.h"
#include "../common/protocol.h"
using namespace std;

thread_local byte_vec k_enc_c2s(32);
thread_local byte_vec k_enc_s2c(32);
thread_local byte_vec k_mac_c2s(32);
thread_local byte_vec k_mac_s2c(32);
thread_local int sockfd;
thread_local bool running;
thread_local uint64_t counter;

static void
close_connection() 
{
    if (sockfd >= 0)
        close(sockfd);
}

static void
init_connection(int conn_fd)
{
    sockfd = conn_fd;

    LOG(INFO, "Client handler started for fd=%d", sockfd);

    string path_to_private_key = DATA_PATH + "/server/priv_server.pem";

    /* get server's private key */
    EVP_PKEY *server_rsa_priv = nullptr;
    readPEMPrivateKey(path_to_private_key, &server_rsa_priv);

    init_secure_channel(sockfd, server_rsa_priv, k_enc_c2s,k_enc_s2c,k_mac_c2s,k_mac_s2c);

    /* free private key */
    EVP_PKEY_free(server_rsa_priv);
}

static void 
connection_handler(int fd)
{
    try 
    {
        init_connection(fd);

        /* test 0: recv with payload */
        counter = 0;
        byte_vec msg;
        uint8_t type;
        recv_message(msg,sockfd,k_enc_c2s,counter,type);
        std::string msg_str(reinterpret_cast<const char*>(msg.data()), msg.size());
        LOG(DEBUG, "[TEST-0] received message: %s. client: %d, counter: %lu, type: %x",
            msg_str.c_str(), sockfd, counter, type);
        
        /* test 1: send with payload */
        send_message(msg, sockfd, k_enc_s2c, counter, type);

        /* test 2: recv no payload */
        recv_message(msg,sockfd,k_enc_c2s,counter,type);
        LOG(DEBUG, "[TEST-2] received message: %s. client: %d, counter: %lu, type: %x",
            msg_str.c_str(), sockfd, counter, type);

        // TODO: implement command_handler and commands
        // while (running)
        //     command_handler(loggedUser);
    }
    catch (const runtime_error &e)
    {
        close_connection();
        LOG(ERROR, "Runtime error: %s", e.what());
    }
    catch (const exception &e)
    {
        close_connection();
        LOG(ERROR, "Exception: %s", e.what());
    }
    catch (...)
    {
        close_connection();
        LOG(ERROR, "Unknown error occurred");
    }

    close_connection();
}

static void
start_server(uint16_t port)
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        perror("socket");
        return;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server_fd, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        close(server_fd);
        return;
    }

    if (listen(server_fd, SOMAXCONN) < 0)
    {
        perror("listen");
        close(server_fd);
        return;
    }

    LOG(INFO, "Server listening on port %d", port);

    while (true)
    {
        sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int conn_fd = accept(server_fd, (sockaddr *)&client_addr, &len);
        if (conn_fd < 0)
        {
            perror("accept");
            continue;
        }

        LOG(INFO, "Client connected: fd=%d", conn_fd);

        // Launch a thread to handle the client
        thread(connection_handler, conn_fd).detach();
    }

    close(server_fd);
}

int main()
{
    start_server(4242);
}

