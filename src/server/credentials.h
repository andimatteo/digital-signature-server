#ifndef _CREDENTIALS
#define _CREDENTIALS

using namespace std;

bool login_user(const string &username, const string &password, bool &firstLogin);
void logout_user(const string &username);
bool change_password(const string &username,const string &newPassword);
void load_credentials();
void save_credentials();

#endif
