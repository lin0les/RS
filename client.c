/*
 * Windows Client for CTF/OSEE Preparation - File Browser
 * Compile on Linux: x86_64-w64-mingw32-gcc -o client.exe client.c -lws2_32 -static
 * Usage: client.exe <listener_ip> [port]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <direct.h>

#define BUFFER_SIZE 8192
#define DEFAULT_PORT 4444

void get_directory_listing(char *output, size_t output_size) {
    WIN32_FIND_DATA findData;
    HANDLE hFind;
    char cwd[MAX_PATH];
    char search_path[MAX_PATH];
    char temp[512];
    
    memset(output, 0, output_size);
    
    // Get current directory
    if (_getcwd(cwd, sizeof(cwd)) == NULL) {
        snprintf(output, output_size, "[-] Failed to get current directory\n");
        return;
    }
    
    snprintf(output, output_size, "\nDirectory: %s\n\n", cwd);
    
    // Search for all files
    snprintf(search_path, sizeof(search_path), "%s\\*", cwd);
    hFind = FindFirstFile(search_path, &findData);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        strcat(output, "[-] Failed to list directory\n");
        return;
    }
    
    do {
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            snprintf(temp, sizeof(temp), "[DIR]  %s\n", findData.cFileName);
        } else {
            ULONGLONG fileSize = ((ULONGLONG)findData.nFileSizeHigh << 32) | findData.nFileSizeLow;
            snprintf(temp, sizeof(temp), "[FILE] %-30s  %llu bytes\n", findData.cFileName, fileSize);
        }
        
        if (strlen(output) + strlen(temp) < output_size - 1) {
            strcat(output, temp);
        }
    } while (FindNextFile(hFind, &findData));
    
    FindClose(hFind);
    strcat(output, "\n");
}

void handle_command(char *cmd, char *output, size_t output_size) {
    char *trimmed_cmd = cmd;
    
    // Trim whitespace
    while (*trimmed_cmd == ' ' || *trimmed_cmd == '\t') {
        trimmed_cmd++;
    }
    
    // Handle 'dir' command
    if (strncmp(trimmed_cmd, "dir", 3) == 0) {
        get_directory_listing(output, output_size);
    }
    // Handle 'cd' command
    else if (strncmp(trimmed_cmd, "cd ", 3) == 0) {
        char *path = trimmed_cmd + 3;
        
        // Trim leading spaces from path
        while (*path == ' ' || *path == '\t') {
            path++;
        }
        
        if (_chdir(path) == 0) {
            char cwd[MAX_PATH];
            _getcwd(cwd, sizeof(cwd));
            snprintf(output, output_size, "[+] Changed directory to: %s\n", cwd);
        } else {
            snprintf(output, output_size, "[-] Failed to change directory to: %s\n", path);
        }
    }
    // Handle 'pwd' command
    else if (strcmp(trimmed_cmd, "pwd") == 0) {
        char cwd[MAX_PATH];
        if (_getcwd(cwd, sizeof(cwd)) != NULL) {
            snprintf(output, output_size, "%s\n", cwd);
        } else {
            snprintf(output, output_size, "[-] Failed to get current directory\n");
        }
    }
    else {
        snprintf(output, output_size, "[-] Unknown command. Supported: dir, cd <path>, pwd\n");
    }
}

int connect_to_listener(const char *host, int port) {
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in server;
    char buffer[BUFFER_SIZE];
    char output[BUFFER_SIZE];
    char hostname[256];
    char username[256];
    char cwd[MAX_PATH];
    DWORD size;
    int bytes_received;
    
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[-] WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }
    
    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        printf("[-] Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    
    // Configure server address
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(host);
    
    printf("[*] Connecting to %s:%d...\n", host, port);
    
    // Connect to listener
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        printf("[-] Connection failed: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    
    printf("[+] Connected to listener\n");
    
    // Receive welcome message
    memset(buffer, 0, BUFFER_SIZE);
    bytes_received = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("%s", buffer);
    }
    
    // Send connection info
    size = sizeof(hostname);
    GetComputerNameA(hostname, &size);
    size = sizeof(username);
    GetUserNameA(username, &size);
    _getcwd(cwd, sizeof(cwd));
    
    snprintf(buffer, BUFFER_SIZE, "[+] %s\\%s @ %s", hostname, username, cwd);
    send(sock, buffer, strlen(buffer), 0);
    
    // Command loop
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        bytes_received = recv(sock, buffer, BUFFER_SIZE - 1, 0);
        
        if (bytes_received <= 0) {
            printf("[-] Connection lost\n");
            break;
        }
        
        buffer[bytes_received] = '\0';
        
        // Remove newline
        buffer[strcspn(buffer, "\r\n")] = 0;
        
        // Check for exit command
        if (strcmp(buffer, "exit") == 0 || strcmp(buffer, "quit") == 0) {
            printf("[*] Exit command received\n");
            break;
        }
        
        // Handle command
        handle_command(buffer, output, sizeof(output));
        
        // Send output back
        send(sock, output, strlen(output), 0);
    }
    
    closesocket(sock);
    WSACleanup();
    return 0;
}

int main(int argc, char *argv[]) {
    char *host;
    int port = DEFAULT_PORT;
    
    if (argc < 2) {
        printf("Usage: %s <listener_ip> [port]\n", argv[0]);
        printf("Example: %s 192.168.1.100 4444\n", argv[0]);
        return 1;
    }
    
    host = argv[1];
    if (argc > 2) {
        port = atoi(argv[2]);
    }
    
    printf("========================================\n");
    printf("Windows Client - File Browser\n");
    printf("========================================\n");
    
    // Retry loop
    while (1) {
        if (connect_to_listener(host, port) == 0) {
            break;
        }
        
        printf("[*] Retrying in 5 seconds...\n");
        Sleep(5000);
    }
    
    return 0;
}
