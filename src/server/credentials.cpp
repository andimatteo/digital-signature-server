#include "common.h"
#include <mutex>
#include <map>
#include <filesystem>
#include <fstream>
#include <iostream>

using namespace std;

struct user
{
    byte_vec passwordHash;
    byte_vec passwordSalt;
    bool firstLogin;

    bool loggedIn;
};

mutex credMutex;
map<string, user> allUsers;

#define CREDENTIALS_FILE "/server/credentials.txt"

bool
save_credentials_internal()
{
    string credPath = DATA_PATH + CREDENTIALS_FILE;

    ofstream file(credPath);
    if (!file.is_open()) {
        LOG(ERROR, "Error opening credentials file!");
        return false;
    }

    for (const auto& pair : allUsers) {
        const string& username = pair.first;
        const user& user = pair.second;

        string password_hash_hex;
        byte_to_hex(user.passwordHash, password_hash_hex);
        string salt_hex;
        byte_to_hex(user.passwordSalt, salt_hex);

        file << username << "\t" << password_hash_hex << "\t" << salt_hex << "\t" << (user.firstLogin ? "true" : "false") << endl;
        LOG(DEBUG, "User %s saved", username.c_str());
    }

    file.close();

    return true;
}

bool
hash_password(const string &password, const byte_vec &salt, byte_vec &hash)
{
    const int hash_length = 32;
    hash.resize(hash_length);

    // TODO: do we want to use this algorithm?
    if (PKCS5_PBKDF2_HMAC(password.c_str(), // Password
                          password.length(), // Password Length
                          reinterpret_cast<const unsigned char*>(salt.data()),  // Salt
                          salt.size(),  // Salt Length
                          100000, // Iterations
                          EVP_sha256(), // Hash function
                          hash_length, // Hash length
                          reinterpret_cast<unsigned char*>(hash.data()) // Output
                        ) == 0)
    {
        return false;
    }

    return true;
}

bool
generate_salt(byte_vec &salt)
{
    salt.resize(16);
    if (RAND_bytes(reinterpret_cast<unsigned char*>(salt.data()), salt.size()) != 1)
    {
        return false;
    }
    return true;
}

bool
add_user(const string user, string password, const bool firstLogin)
{
    byte_vec password_hash;
    byte_vec password_salt;
    if (!generate_salt(password_salt))
    {
        memzero(password);
        return false;
    }
    if (!hash_password(password, password_salt, password_hash))
    {
        memzero(password);
        return false;
    }
    memzero(password);

    allUsers[user] = {password_hash, password_salt, firstLogin, false};
    LOG(INFO, "User %s added", user.c_str());

    return true;
}

bool
login_user(const string &username, const string &password, bool &firstLogin)
{
    lock_guard<mutex> lock(credMutex);

    auto it = allUsers.find(username);
    if (it == allUsers.end()) {
        LOG(INFO, "User %s not found", username.c_str());
        return false;
    }
    user& user = it->second;
    byte_vec password_hash;
    if (!hash_password(password, user.passwordSalt, password_hash))
    {
        LOG(ERROR, "Error hashing password!");
        return false;
    }

    if (password_hash == user.passwordHash)
    {
        if (user.loggedIn)
        {
            LOG(INFO, "User %s already logged in", username.c_str());
            return false;
        }

        firstLogin = user.firstLogin;
        user.loggedIn = true;
        return true;
    }

    LOG(INFO, "Wrong password");
    return false;
}

void
logout_user(const string &username)
{
    lock_guard<mutex> lock(credMutex);

    auto it = allUsers.find(username);
    if (it == allUsers.end()) {
        return;
    }

    user& user = it->second;
    user.loggedIn = false;
}

bool
change_password(const string &username, const string &newPassword)
{
    lock_guard<mutex> lock(credMutex);

    auto it = allUsers.find(username);
    if (it == allUsers.end()) {
        LOG(INFO, "User %s not found", username.c_str());
        return false;
    }
    user& user = it->second;

    byte_vec password_hash;
    byte_vec password_salt;
    if (!generate_salt(password_salt))
    {
        LOG(ERROR, "Error generating salt!");
        return false;
    }
    if (!hash_password(newPassword, password_salt, password_hash))
    {
        LOG(ERROR, "Error hashing password!");
        return false;
    }

    byte_vec old_password_hash = user.passwordHash;
    byte_vec old_password_salt = user.passwordSalt;
    user.passwordHash = password_hash;
    user.passwordSalt = password_salt;
    user.firstLogin = false;

    if (!save_credentials_internal())
    {
        LOG(ERROR, "Error saving credentials!");
        user.passwordHash = old_password_hash;
        user.passwordSalt = old_password_salt;
        user.firstLogin = true;
        return false;
    }

    return true;
}

void
load_credentials()
{
    lock_guard<mutex> lock(credMutex);
    
    string credPath = DATA_PATH + CREDENTIALS_FILE;

    ifstream file(credPath);
    if (!file.is_open()) {
        LOG(WARN, "Error opening credentials file, generating new one");

        add_user("utente", "pass", true);
        add_user("utente2", "password", true);
        add_user("prova", "prova", false);
        
        save_credentials_internal();
        return;
    }

    string line;
    while (getline(file, line)) {
        size_t pos1 = line.find('\t');
        if (pos1 == string::npos) {
            LOG(WARN, "Invalid line in credentials file: %s", line.c_str());
            continue;
        }
        size_t pos2 = line.find('\t', pos1 + 1);
        if (pos2 == string::npos) {
            LOG(WARN, "Invalid line in credentials file: %s", line.c_str());
            continue;
        }
        size_t pos3 = line.find('\t', pos2 + 1);
        if (pos3 == string::npos) {
            LOG(WARN, "Invalid line in credentials file: %s", line.c_str());
            continue;
        }
        
        string user = line.substr(0, pos1);

        string hash_hex = line.substr(pos1 + 1, pos2 - pos1 - 1);
        byte_vec hash;
        hex_to_byte(hash_hex, hash);
        
        string salt_hex = line.substr(pos2 + 1, pos3 - pos2 - 1);
        byte_vec salt;
        hex_to_byte(salt_hex, salt);
        
        bool first_login = (line.substr(pos3 + 1) == "true");

        allUsers[user] = {hash, salt, first_login, false};

        LOG(INFO, "User %s loaded", user.c_str());
    }

    file.close();

    LOG(INFO, "All users loaded!");
}

void
save_credentials()
{
    lock_guard<mutex> lock(credMutex);
    save_credentials_internal();
}
