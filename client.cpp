#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "crypto.h"

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 12345

int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in server_addr = {};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Connection failed" << std::endl;
        return -1;
    }

    std::cout << "Connected to server." << std::endl;
    std::string username, password, message;
    std::cout << "Enter username: ";
    std::cin >> username;
    std::cout << "Enter password: ";
    std::cin >> password;

    AESCryptor cryptor;
    while (true) {
        std::cout << "Enter message: ";
        std::cin >> message;
        std::string encrypted_message = cryptor.encrypt(username + ": " + message);
        send(sock, encrypted_message.c_str(), encrypted_message.length(), 0);
    }

    close(sock);
    return 0;
}