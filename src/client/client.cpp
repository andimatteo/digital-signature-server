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
uint64_t counter = 0; // TODO: is it ok to always start the counter at 0?
int sockfd;

typedef enum
{
    CREATE,
    SIGN,
    GET,
    DELETE,
    EXIT
} CMD;

string error_text(uint8_t type)
{
    switch (type & 0b11111100)
    {
    case ERROR_DELETED_KEYS:
        return "\033[31mERROR\033[0m: Keys for this user are deleted";
    case ERROR_KEYS_ALREADY_PRESENT:
        return "\033[31mERROR\033[0m: Keys for this user are already present";
    case ERROR_INVALID_USER:
        return "\033[31mERROR\033[0m: Invalid username";
    case ERROR_INVALID_PASSWORD:
        return "\033[31mERROR\033[0m: Invalid password";
    case ERROR_MISSING_KEYS:
        return "\033[31mERROR\033[0m: Keys for this user are missing";
    case ERROR_PARTIAL_DELETION:
        return "\033[31mERROR\033[0m: Deletion of keys was only partial, please retry or contact an administrator";
    case ERROR_INVALID_DOCUMENT:
        return "\033[31mERROR\033[0m: Invalid document";
    case ERROR_INVALID_PARAMETERS:
        return "\033[31mERROR\033[0m: Invalid parameters";
    case ERROR_INVALID_CREDENTIALS:
        return "\033[31mERROR\033[0m: Submitted credentials are not valid";
    case ERROR_INTERNAL:
        return "\033[31mERROR\033[0m: Internal server error";
    default:
        return "\033[31mERROR\033[0m: Unknown Error";
    }
}

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

bool cmd_change_password()
{
    cout << endl << "This is your first access, you need to change your password" << endl;

    while (true)
    {
        string password;

        cout << "New password: ";
        cin >> password;
        cin.ignore(INT_MAX, '\n');

        if (!validate_password(password))
        {
            cout << "Invalid password" << endl << endl;
            continue;
        }
        
        byte_vec payload;
        for (size_t i = 0; i < 32; i++)
        {
            if (i < password.length())
            {
                payload.push_back(password[i]);
            }
            else
            {
                payload.push_back('\0');
            }
        }

        send_message(payload, sockfd, k_enc_c2s, counter, 0x00);

        byte_vec msg;
        uint8_t type;
        if (!recv_message(msg, sockfd, k_enc_s2c, counter, type))
        {
            return false;
        }

        switch (type)
        {
            case 0x00:
                cout << "Password change successful" << endl;
                return true;
                break;
            
            default:
                cout << error_text(type) << endl << endl;
                break;
        }

    }
}

bool cmd_login() {

    cout << "Login required" << endl;

    while (true)
    {
        string username;

        cout << "Username: ";
        cin >> username;
        cin.ignore(INT_MAX, '\n');

        if (!validate_username(username))
        {
            cout << "Invalid Username" << endl << endl;
            continue;
        }

        string password;

        cout << "Password: ";
        cin >> password;
        cin.ignore(INT_MAX, '\n');

        if (!validate_password(password))
        {
            cout << "Invalid Password" << endl << endl;
            continue;
        }
        
        byte_vec payload;
        for (size_t i = 0; i < 32; i++)
        {
            if (i < username.length())
            {
                payload.push_back(username[i]);
            }
            else
            {
                payload.push_back('\0');
            }
        }
        for (size_t i = 0; i < 32; i++)
        {
            if (i < password.length())
            {
                payload.push_back(password[i]);
            }
            else
            {
                payload.push_back('\0');
            }
        }

        send_message(payload, sockfd, k_enc_c2s, counter, 0x00);

        byte_vec msg;
        uint8_t type;
        if (!recv_message(msg, sockfd, k_enc_s2c, counter, type))
        {
            return false;
        }

        switch (type)
        {
            case 0x00:
                cout << "Login successful" << endl;
                return true;
                break;

            case 0x01:
                cout << "Login successful" << endl;
                return cmd_change_password();
                break;
            
            default:
                cout << error_text(type) << endl << endl;
                break;
        }

    }
}

bool cmd_create(){

    string password;

    cout << "Provide a password for your keys: ";
    cin >> password;
    cin.ignore(INT_MAX, '\n');

    if (!validate_password(password))
    {
        cout << "Invalid Password" << endl;
        return true;
    }
    
    byte_vec payload;
    for (size_t i = 0; i < 32; i++)
    {
        if (i < password.length())
        {
            payload.push_back(password[i]);
        }
        else
        {
            payload.push_back('\0');
        }
    }

    send_message(payload, sockfd, k_enc_c2s, counter, CREATE_KEYS);

    byte_vec msg;
    uint8_t type;
    if (!recv_message(msg, sockfd, k_enc_s2c, counter, type))
    {
        return false;
    }

    switch (type & 0b11111100)
    {
        case SUCCESSFUL:
            cout << "Keys created successfully" << endl;
            break;
        
        default:
            cout << error_text(type) << endl;
            break;
    }

    return true;
}

bool cmd_sign(){

    string password;

    cout << "Provide the password for your keys: ";
    cin >> password;
    cin.ignore(INT_MAX, '\n');

    if (!validate_password(password))
    {
        cout << "Invalid Password" << endl;
        return true;
    }

    string filename;

    cout << "Select document: ";
    cin >> filename;
    cin.ignore(INT_MAX, '\n');

    
    byte_vec payload;
    for (size_t i = 0; i < 32; i++)
    {
        if (i < password.length())
        {
            payload.push_back(password[i]);
        }
        else
        {
            payload.push_back('\0');
        }
    }

    // TODO: Add file to payload (after all the checks)
    payload.push_back('a');payload.push_back('b');payload.push_back('A');payload.push_back('B');
    payload.push_back('a');payload.push_back('b');payload.push_back('A');payload.push_back('B');
    payload.push_back('a');payload.push_back('b');payload.push_back('A');payload.push_back('B');
    payload.push_back('a');payload.push_back('b');payload.push_back('A');payload.push_back('B');
    payload.push_back('a');payload.push_back('b');payload.push_back('A');payload.push_back('B');
    payload.push_back('a');payload.push_back('b');payload.push_back('A');payload.push_back('B');
    payload.push_back('a');payload.push_back('b');payload.push_back('A');payload.push_back('B');
    payload.push_back('a');payload.push_back('b');payload.push_back('A');payload.push_back('B');

    send_message(payload, sockfd, k_enc_c2s, counter, SIGN_DOC);

    byte_vec msg;
    uint8_t type;
    if (!recv_message(msg, sockfd, k_enc_s2c, counter, type))
    {
        return false;
    }
    string response(msg.begin(), msg.end());

    switch (type & 0b11111100)
    {
        case SUCCESSFUL:
            // TODO: Print signature properly (or send to file), now is just a blob of bytes
            cout << "Retrieved signature:" << endl << response << endl;
            break;
        
        default:
            cout << error_text(type) << endl;
            break;
    }

    return true;
}

bool cmd_get(){

    string username;

    cout << "Retrieve keys for user: ";
    cin >> username;
    cin.ignore(INT_MAX, '\n');

    if (!validate_username(username))
    {
        cout << "Invalid username" << endl;
        return true;
    }
    
    byte_vec payload;
    for (size_t i = 0; i < 32; i++)
    {
        if (i < username.length())
        {
            payload.push_back(username[i]);
        }
        else
        {
            payload.push_back('\0');
        }
    }

    send_message(payload, sockfd, k_enc_c2s, counter, GET_PUBLIC_KEY);

    byte_vec msg;
    uint8_t type;
    if (!recv_message(msg, sockfd, k_enc_s2c, counter, type))
    {
        return false;
    }
    string response(msg.begin(), msg.end());

    switch (type & 0b11111100)
    {
        case SUCCESSFUL:
            cout << "Retrieved public key:" << endl << response << endl;
            break;
        
        default:
            cout << error_text(type) << endl;
            break;
    }

    return true;
}

bool cmd_delete(){
    
    byte_vec empty;

    send_message(empty, sockfd, k_enc_c2s, counter, DELETE_KEYS);

    byte_vec msg;
    uint8_t type;
    if (!recv_message(msg, sockfd, k_enc_s2c, counter, type))
    {
        return false;
    }

    switch (type & 0b11111100)
    {
        case SUCCESSFUL:
            cout << "Keys deleted successfully" << endl;
            break;
        
        default:
            cout << error_text(type) << endl;
            break;
    }

    return true;
}


CMD wait_for_command()
{
    // TODO: change styling
    const string GREEN = "\033[32m";
    const string RESET = "\033[0m";

    cout << endl;
    cout << "Available Commands:\n";
    cout << GREEN << "1) CreateKeys" << RESET << " - Create a new key pair\n";
    cout << GREEN << "2) SignDoc" << RESET << " - Sign a document\n";
    cout << GREEN << "3) GetPublicKey" << RESET << " - Get a user's public key\n";
    cout << GREEN << "4) DeleteKeys" << RESET << " - Delete your key pair\n";
    cout << GREEN << "5) Quit" << RESET << " - Exit the application\n";
    cout << endl;

    while (true)
    {
        string command;
        cout << "> ";
        cin >> command;
        cin.ignore(INT_MAX, '\n');

        if (command == "CreateKeys" || command == "createkeys" || command == "1")
            return CREATE;
        else if (command == "SignDoc" || command == "createkeys" || command == "2")
            return SIGN;
        else if (command == "GetPublicKey" || command == "createkeys" || command == "3")
            return GET;
        else if (command == "DeleteKeys" || command == "createkeys" || command == "4")
            return DELETE;
        else if (command == "Quit" || command == "quit" || command == "5" || command == "q" || command == "Exit" || command == "exit")
            return EXIT;
        else
            cout << "Unknown command (" << command << ")!" << endl;
    }

}

int main()
{
    try 
    {
        client_init_connection();

        bool running = cmd_login();

        while(running)
        {
            CMD command = wait_for_command();
            switch (command)
            {
                case CREATE:
                    running = cmd_create();
                    break;
                case SIGN:
                    running = cmd_sign();
                    break;
                case GET:
                    running = cmd_get();
                    break;
                case DELETE:
                    running = cmd_delete();
                    break;
                case EXIT:
                    running = false;
                    break;
                
                default:
                    error("Invalid command");
                    break;
            }
        }
    }
    catch (const runtime_error &e)
    {
        LOG(ERROR, "Runtime error: %s", e.what());
        close_connection();
        return 1;
    }
    catch (const exception &e)
    {
        LOG(ERROR, "Exception: %s", e.what());
        close_connection();
        return 1;
    }
    catch (...)
    {
        LOG(ERROR, "Unknown error occurred");
        close_connection();
        return 1;
    }

    close_connection();

    return 0;
}

