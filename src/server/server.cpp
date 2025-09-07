#include <iostream>
#include <thread>
#include <mutex>
#include <sys/socket.h>
#include <netinet/in.h>
#include <filesystem>
#include <fstream>
#include "../common/common.h"
#include "../common/protocol.h"
#include "../common/constant.h"
#include "../server/credentials.h"
using namespace std;

thread_local byte_vec k_enc_c2s(32);
thread_local byte_vec k_enc_s2c(32);
thread_local byte_vec k_mac_c2s(32);
thread_local byte_vec k_mac_s2c(32);
thread_local int sockfd;
thread_local uint64_t counter;

#define SESSION_NEW 0x01
#define SESSION_INITIALIZED 0x02
#define SESSION_FIRST_LOGIN 0x03
#define SESSION_LOGGED_IN 0x04
#define SESSION_ENDED 0x05
#define SESSION_ERROR 0xFF
thread_local uint8_t session_status;
thread_local string session_user = "NONE";

#define KEYS_DIR "/server/keys/"

mutex keyMutex;

static void
close_connection() 
{
    if (sockfd >= 0)
        close(sockfd);

    memzero(k_enc_c2s);
    memzero(k_enc_s2c);
    memzero(k_mac_c2s);
    memzero(k_mac_s2c);
    counter = 0;
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

    init_secure_channel(sockfd, server_rsa_priv, k_enc_c2s, k_enc_s2c, k_mac_c2s, k_mac_s2c);

    // TODO: is it really ok to always start at 0???
    counter = 0;

    /* free private key */
    EVP_PKEY_free(server_rsa_priv);
}

static uint8_t
handle_password_change()
{
    byte_vec msg;
    uint8_t type;
    if ( !recv_message(msg, sockfd, k_enc_c2s, counter, type) )
    {
        session_status = SESSION_ENDED;
        LOG(INFO, "Socket closed or incomplete message received, ending session.");
        return 0xFF;
    }

    if (msg.size() < 32)
    {
        memzero(msg);
        return ERROR_INVALID_PARAMETERS;
    }

    char psw_array[33];
    copy(msg.begin(), msg.begin() + 32, psw_array);
    psw_array[32] = '\0';

    memzero(msg);
    
    string psw(psw_array);

    fill(psw_array, psw_array + 32, '\0');
    
    if ( !validate_password(psw) )
    {
        memzero(psw);
        return ERROR_INVALID_PASSWORD;
    }
    if ( !change_password(session_user, psw) )
    {
        memzero(psw);
        return ERROR_INTERNAL;
    }
    memzero(psw);

    LOG(INFO, "Password changed");

    session_status = SESSION_LOGGED_IN;
    
    return 0x00;
}

static uint8_t
handle_login()
{
    byte_vec msg;
    uint8_t type;
    if ( !recv_message(msg, sockfd, k_enc_c2s, counter, type) )
    {
        session_status = SESSION_ENDED;
        LOG(INFO, "Socket closed or incomplete message received, ending session.");
        return 0xFF;
    }
    
    if (msg.size() < 64)
    {
        memzero(msg);
        LOG(INFO, "Wrong message size");
        return ERROR_INVALID_PARAMETERS;
    }

    char user_array[33];
    copy(msg.begin(), msg.begin() + 32, user_array);
    user_array[32] = '\0';

    char psw_array[33];
    copy(msg.begin() + 32, msg.begin() + 64, psw_array);
    psw_array[32] = '\0';

    memzero(msg);

    string user(user_array);
    string psw(psw_array);

    fill(psw_array, psw_array + 32, '\0');
    
    if ( !validate_username(user) )
    {
        memzero(psw);
        LOG(INFO, "Invalid username");
        return ERROR_INVALID_USER;
    }
    if ( !validate_password(psw) )
    {
        memzero(psw);
        LOG(INFO, "Invalid password");
        return ERROR_INVALID_PASSWORD;
    }

    bool first = true;
    if ( !login_user(user, psw, first) )
    {
        memzero(psw);
        return ERROR_INVALID_CREDENTIALS;
    }
    session_user = user;
    memzero(psw);

    if (first)
    {
        LOG(INFO, "First login, changing password");
        session_status = SESSION_FIRST_LOGIN;
        return 0x01;
    }
    else
    {
        session_status = SESSION_LOGGED_IN;
        return 0x00;
    }

}

static uint8_t
create_keys(const byte_vec& msg)
{
    lock_guard<mutex> lock(keyMutex);

    string priv_path = DATA_PATH + KEYS_DIR + session_user + "_privkey.pem";
    string pub_path = DATA_PATH + KEYS_DIR + session_user + "_pubkey.pem";

    if (filesystem::exists(priv_path) || filesystem::exists(pub_path))
    {
        ifstream file(priv_path);
        if (!file.is_open()) {
            LOG(ERROR, "Failed to open key file: %s", priv_path.c_str());
            return ERROR_INTERNAL;
        }
        bool deleted = file.peek() == ifstream::traits_type::eof();
        file.close();

        LOG(INFO, (deleted ? "Keys are deleted" : "Keys already present"));
        return (deleted ? ERROR_DELETED_KEYS : ERROR_KEYS_ALREADY_PRESENT);
    }
    
    if (msg.size() < 32)
    {
        LOG(INFO, "Message too short");
        return ERROR_INVALID_PASSWORD;
    }

    // TODO: Do we want to use this algorithm?

    EVP_PKEY* keypair = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
    {
        LOG(WARN, "Failed to generate RSA key pair for user %s", session_user.c_str());
        return ERROR_INTERNAL;
    }
        
    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        LOG(WARN, "Failed to generate RSA key pair for user %s", session_user.c_str());
        return ERROR_INTERNAL;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        LOG(WARN, "Failed to generate RSA key pair for user %s", session_user.c_str());
        return ERROR_INTERNAL;
    }

    if (EVP_PKEY_keygen(ctx, &keypair) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        LOG(WARN, "Failed to generate RSA key pair for user %s", session_user.c_str());
        return ERROR_INTERNAL;
    }

    EVP_PKEY_CTX_free(ctx);

    if (!keypair)
    {
        LOG(WARN, "Failed to generate RSA key pair for user %s", session_user.c_str());
        return ERROR_INTERNAL;
    }

    BIO* pub_bio = BIO_new_file(pub_path.c_str(), "w");
    if (!pub_bio)
    {
        EVP_PKEY_free(keypair);
        LOG(WARN, "Failed to open public key file for writing: %s", pub_path.c_str());
        return ERROR_INTERNAL;
    }

    if (PEM_write_bio_PUBKEY(pub_bio, keypair) <= 0)
    {
        BIO_free(pub_bio);
        EVP_PKEY_free(keypair);
        LOG(WARN, "Failed to write public key to file: %s", pub_path.c_str());
        return ERROR_INTERNAL;
    }

    BIO_free(pub_bio);

    char psw_array[33];
    copy(msg.begin(), msg.begin() + 32, psw_array);
    psw_array[32] = '\0';

    string psw(psw_array);

    fill(psw_array, psw_array + 32, '\0');

    if ( !validate_password(psw) )
    {
        memzero(psw);
        LOG(INFO, "Invalid password");
        return ERROR_INVALID_PASSWORD;
    }

    BIO* priv_bio = BIO_new_file(priv_path.c_str(), "w");
    if (!priv_bio)
    {
        EVP_PKEY_free(keypair);
        LOG(WARN, "Failed to open private key file for writing: %s", priv_path.c_str());
        memzero(psw);
        return ERROR_INTERNAL;
    }
    if (PEM_write_bio_PrivateKey(priv_bio, keypair, EVP_aes_256_cbc(), NULL, 0, NULL, (void*)psw.c_str()) <= 0)
    {
        BIO_free(priv_bio);
        EVP_PKEY_free(keypair);
        LOG(WARN, "Failed to write private key to file: %s", priv_path.c_str());
        memzero(psw);
        return ERROR_INTERNAL;
    }

    memzero(psw);
    BIO_free(priv_bio);
    EVP_PKEY_free(keypair);
    
    LOG(INFO, "Keys creation successful");
    return SUCCESSFUL;
}

static uint8_t
sign_doc(const byte_vec& msg, byte_vec& response)
{
    lock_guard<mutex> lock(keyMutex);
    
    if (msg.size() < 33)
    {
        LOG(INFO, "Message too short");
        return ERROR_INVALID_PARAMETERS;
    }

    char psw_array[33];
    copy(msg.begin(), msg.begin() + 32, psw_array);
    psw_array[32] = '\0';

    string psw(psw_array);

    fill(psw_array, psw_array + 32, '\0');

    if ( !validate_password(psw) )
    {
        memzero(psw);
        LOG(INFO, "Invalid password");
        return ERROR_INVALID_PASSWORD;
    }

    string priv_path = DATA_PATH + KEYS_DIR + session_user + "_privkey.pem";

    if (!filesystem::exists(priv_path))
    {
        LOG(INFO, "Keys are missing");
        return ERROR_MISSING_KEYS;
    }
    
    ifstream file(priv_path);
    if (!file.is_open()) {
        LOG(ERROR, "Failed to open private key file: %s", priv_path.c_str());
        return ERROR_INTERNAL;
    }
    bool deleted = file.peek() == ifstream::traits_type::eof();
    file.close();

    if (deleted)
    {
        LOG(INFO, "Keys have been deleted");
        return ERROR_DELETED_KEYS;
    }

    const byte_vec document(msg.begin()+32, msg.end());

    if (document.empty())
    {
        memzero(psw);
        LOG(INFO, "Document is empty");
        return ERROR_INVALID_DOCUMENT;
    }

    // TODO: Do we want to use this algorithm?

    EVP_PKEY* privkey = nullptr;
    readPEMPrivateKey(priv_path, &privkey, psw.c_str());
    memzero(psw);

    signRsaSha256(response, document, privkey);
    EVP_PKEY_free(privkey);

    if (response.empty()) {
        LOG(ERROR, "Failed to sign document for user %s", session_user.c_str());
        return ERROR_INTERNAL;
    }

    LOG(INFO, "Document signed");
    return SUCCESSFUL;
}

static uint8_t
get_public_key(const byte_vec& msg, byte_vec& response)
{
    lock_guard<mutex> lock(keyMutex);

    if (msg.size() < 32)
    {
        return ERROR_INVALID_USER;
    }

    char user_array[33];
    copy(msg.begin(), msg.begin() + 32, user_array);
    user_array[32] = '\0';

    string user(user_array);
    
    if ( !validate_username(user) )
    {
        return ERROR_INVALID_USER;
    }
    
    string pub_path = DATA_PATH + KEYS_DIR + user + "_pubkey.pem";

    if (!filesystem::exists(pub_path))
    {
        LOG(INFO, "Keys are missing");
        return ERROR_MISSING_KEYS;
    }
    
    ifstream file(pub_path);
    if (!file.is_open()) {
        LOG(ERROR, "Failed to open public key file: %s", pub_path.c_str());
        return ERROR_INTERNAL;
    }
    bool deleted = file.peek() == ifstream::traits_type::eof();
    file.close();

    if (deleted)
    {
        LOG(INFO, "Keys have been deleted");
        return ERROR_DELETED_KEYS;
    }

    FILE* file_PEM_pubkey = fopen(pub_path.c_str(), "r");
    if (!file_PEM_pubkey) {
        LOG(ERROR, "Failed to open public key file: %s", pub_path.c_str());
        return ERROR_INTERNAL;
    }

    fseek(file_PEM_pubkey, 0, SEEK_END);
    long int PEM_pubkey_size = ftell(file_PEM_pubkey);
    fseek(file_PEM_pubkey, 0, SEEK_SET);

    response.resize(PEM_pubkey_size);

    int bytesRead = fread(response.data(), 1, PEM_pubkey_size, file_PEM_pubkey);
    if (bytesRead < PEM_pubkey_size) {
        fclose(file_PEM_pubkey);
        LOG(ERROR, "Failed to read public key from file: %s", pub_path.c_str());
        return ERROR_INTERNAL;
    }
    fclose(file_PEM_pubkey);

    LOG(INFO, "Public key retrieved for user %s", user.c_str());
    return SUCCESSFUL;
}

static uint8_t
delete_keys()
{
    lock_guard<mutex> lock(keyMutex);

    string priv_path = DATA_PATH + KEYS_DIR + session_user + "_privkey.pem";
    string pub_path = DATA_PATH + KEYS_DIR + session_user + "_pubkey.pem";

    int error = 0;

    if (filesystem::exists(priv_path))
    {
        ofstream file(priv_path, ofstream::out | ofstream::trunc);
        if (!file.is_open()) {
            LOG(ERROR, "Failed to open key file: %s", priv_path.c_str());
            error += 1;
        }
        else
        {
            LOG(INFO, "Deleted key: %s", priv_path.c_str());
            file.close();
        }
    }

    if (filesystem::exists(pub_path))
    {
        ofstream file(pub_path, ofstream::out | ofstream::trunc);
        if (!file.is_open()) {
            LOG(ERROR, "Failed to open key file: %s", priv_path.c_str());
            error += 1;
        }
        else
        {
            LOG(INFO, "Deleted key: %s", priv_path.c_str());
            file.close();
        }
    }

    if (error == 0)
    {
        return SUCCESSFUL;
    }
    else
    {
        return (error == 1 ? ERROR_PARTIAL_DELETION : ERROR_INTERNAL );
    }
}

static void
command_handler()
{
    byte_vec msg;
    uint8_t type;
    if ( !recv_message(msg, sockfd, k_enc_c2s, counter, type) )
    {
        session_status = SESSION_ENDED;
        LOG(INFO, "Socket closed or incomplete message received, ending session.");
        return;
    }

    // TODO: remove "& 0x03" to check for errors? Useless probably
    byte_vec empty;
    byte_vec response;
    uint8_t resp_code;

    switch (type & 0b00000011)
    {
    case CREATE_KEYS:
        LOG(INFO, "Command received: CreateKeys");

        resp_code = create_keys(msg);

        if (msg.size() != 0)
            memzero(msg);

        send_message(empty, sockfd, k_enc_s2c, counter, 0x00 | resp_code);
        break;
    case SIGN_DOC:
        LOG(INFO, "Command received: SignDoc");

        resp_code = sign_doc(msg, response);

        if (msg.size() != 0)
            fill(msg.begin(), msg.begin() + 32, '\0');

        send_message(response, sockfd, k_enc_s2c, counter, 0x01 | resp_code);
        break;
    case GET_PUBLIC_KEY:
        LOG(INFO, "Command received: GetPublicKey");

        resp_code = get_public_key(msg, response);

        send_message(response, sockfd, k_enc_s2c, counter, 0x02 | resp_code);
        break;
    case DELETE_KEYS:
        LOG(INFO, "Command received: DeleteKeys");

        resp_code = delete_keys();

        send_message(empty, sockfd, k_enc_s2c, counter, 0x03 | resp_code);
        break;
    
    default:
        error("Invalid request type");
        break;
    }
}

static void 
connection_handler(int fd)
{
    session_status = SESSION_NEW;

    LOG(INFO, "New thread created");

    try 
    {
        init_connection(fd);
        session_status = SESSION_INITIALIZED;
        LOG(INFO, "Session init complete");

        while (session_status == SESSION_INITIALIZED)
        {
            uint8_t resp_type = handle_login();

            if (session_status == SESSION_ENDED)
                break;

            byte_vec empty;
            send_message(empty, sockfd, k_enc_s2c, counter, resp_type);
        }
        
        while (session_status == SESSION_FIRST_LOGIN)
        {
            uint8_t resp_type = handle_password_change();
            
            if (session_status == SESSION_ENDED)
                break;

            byte_vec empty;
            send_message(empty, sockfd, k_enc_s2c, counter, resp_type);
        }

        if ( session_user.compare("NONE") == 0 || session_status != SESSION_LOGGED_IN ) 
        {
            if (session_status == SESSION_ENDED)
            {
                logout_user(session_user);
                close_connection();
                LOG(INFO, "Connection closed");
                return;
            }
            error("Login Error");
        }

        LOG(INFO, "Login complete!");

        while (session_status == SESSION_LOGGED_IN)
            command_handler();

    }
    catch (const runtime_error &e)
    {
        session_status = SESSION_ERROR;
        logout_user(session_user);
        close_connection();
        LOG(ERROR, "Runtime error: %s", e.what());
        return;
    }
    catch (const exception &e)
    {
        session_status = SESSION_ERROR;
        logout_user(session_user);
        close_connection();
        LOG(ERROR, "Exception: %s", e.what());
        return;
    }
    catch (...)
    {
        session_status = SESSION_ERROR;
        logout_user(session_user);
        close_connection();
        LOG(ERROR, "Unknown error occurred");
        return;
    }

    logout_user(session_user);
    close_connection();
    LOG(INFO, "Connection closed");
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

extern logLevel minimumLevel;

int main(int argc, char * argv[])
{
    if (argc > 1)
        minimumLevel = (logLevel)atoi(argv[1]);
    load_credentials();
    start_server(4242);
    save_credentials();
}
