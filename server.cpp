#include <iostream>
#include <fstream>
#include <unordered_map>
#include <sstream>
#include <vector>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <unistd.h>
#include "crypto.h"

#define PORT 12345

std::unordered_map<std::string, std::string> users; // username to hashed password
pthread_mutex_t users_mutex = PTHREAD_MUTEX_INITIALIZER;

void loadUsers() {
    std::ifstream file("users.txt");
    std::string line, username, password;
    while (getline(file, line)) {
        std::istringstream iss(line);
        if (getline(iss, username, ':') && getline(iss, password)) {
            users[username] = password;
        }
    }
    file.close();
}

void saveUser(const std::string& username, const std::string& password) {
    std::ofstream file("users.txt", std::ios::app);
    file << username << ":" << password << "\n";
    file.close();
}

std::string hashPassword(const std::string& password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password.c_str(), password.size());
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for (unsigned char i : hash) {
        ss << std::hex << static_cast<int>(i);
    }
    return ss.str();
}

struct client_info {
    int sock;
};

void *handle_client(void *arg) {
    client_info info = static_cast<client_info>(arg);
    AESCryptor cryptor;
    char buffer[1024];
    int bytes_read;

    while ((bytes_read = recv(info->sock, buffer, sizeof(buffer), 0)) > 0) {
        buffer[bytes_read] = '\0';
        std::string decrypted_msg = cryptor.decrypt(std::string(buffer, bytes_read));
        std::cout << "Decrypted message: " << decrypted_msg << std::endl;

        pthread_mutex_lock(&users_mutex);
        for (auto &user : users) {
            if (user.first != decrypted_msg.substr(0, decrypted_msg.find(":"))) {
                std::string encrypted_msg = cryptor.encrypt(decrypted_msg);
                send(info->sock, encrypted_msg.c_str(), encrypted_msg.size(), 0);
            }
        }
        pthread_mutex_unlock(&users_mutex);
    }

    close(info->sock);
    delete info;
    return nullptr;
}

int main() {
    loadUsers();
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in server_addr = {};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(server_sock, 5);
    std::cout << "Server listening on port " << PORT << std::endl;

    while (true) {
        client_info *info = new client_info;
        socklen_t addrlen = sizeof(server_addr);
        info->sock = accept(server_sock, (struct sockaddr *)&server_addr, &addrlen);
        pthread_t tid;
        pthread_create(&tid, nullptr, handle_client, info);
        pthread_detach(tid);
    }

    return 0;
}