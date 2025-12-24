/*
 * Linux Listener for CTF/OSEE Preparation - Version 3
 * Compile: gcc -o listener listener.c
 * Usage: ./listener [port]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#define BUFFER_SIZE 16384
#define DEFAULT_PORT 4444

int server_fd = -1;

void cleanup(int sig) {
    printf("\n[*] Shutting down listener...\n");
    if (server_fd != -1) {
        close(server_fd);
    }
    exit(0);
}

void print_help() {
    printf("\n=== Available Commands ===\n");
    printf("  dir              - List files and directories\n");
    printf("  cd <path>        - Change directory\n");
    printf("  pwd              - Print working directory\n");
    printf("  cat <file>       - Read file content\n");
    printf("  type <file>      - Read file content (Windows style)\n");
    printf("  sysinfo          - Get system information\n");
    printf("  exit/quit        - Close connection\n");
    printf("  help             - Show this help\n");
    printf("==========================\n\n");
}

void handle_client(int client_fd, struct sockaddr_in client_addr) {
    char buffer[BUFFER_SIZE];
    char command[256];
    ssize_t bytes_received;
    int total_received;
    
    printf("[+] Connection from %s:%d\n", 
           inet_ntoa(client_addr.sin_addr), 
           ntohs(client_addr.sin_port));
    
    // Send welcome message
    const char *welcome = "[*] Connected to listener\n";
    send(client_fd, welcome, strlen(welcome), 0);
    
    // Receive initial connection info
    memset(buffer, 0, BUFFER_SIZE);
    bytes_received = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
    
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("%s\n", buffer);
    }
    
    print_help();
    
    while (1) {
        // Get command from user
        printf("remote> ");
        fflush(stdout);
        
        if (fgets(command, sizeof(command), stdin) == NULL) {
            break;
        }
        
        // Remove newline
        command[strcspn(command, "\n")] = 0;
        
        // Check for local help command
        if (strcmp(command, "help") == 0) {
            print_help();
            continue;
        }
        
        // Check for exit command
        if (strcmp(command, "exit") == 0 || strcmp(command, "quit") == 0) {
            send(client_fd, "exit\n", 5, 0);
            printf("[*] Closing connection\n");
            break;
        }
        
        // Send command to client
        strcat(command, "\n");
        if (send(client_fd, command, strlen(command), 0) <= 0) {
            printf("[-] Send failed\n");
            break;
        }
        
        // Receive response (may be large for sysinfo)
        memset(buffer, 0, BUFFER_SIZE);
        total_received = 0;
        
        while (1) {
            bytes_received = recv(client_fd, buffer + total_received, 
                                 BUFFER_SIZE - total_received - 1, 0);
            
            if (bytes_received <= 0) {
                printf("[-] Connection lost\n");
                close(client_fd);
                return;
            }
            
            total_received += bytes_received;
            
            // Check if we received the end marker
            if (total_received >= 3) {
                char *end_marker = strstr(buffer, "<<<END>>>");
                if (end_marker != NULL) {
                    *end_marker = '\0';
                    break;
                }
            }
            
            // Safety check
            if (total_received >= BUFFER_SIZE - 1) {
                break;
            }
        }
        
        printf("%s", buffer);
    }
    
    close(client_fd);
}

int main(int argc, char *argv[]) {
    int port = DEFAULT_PORT;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd;
    int opt = 1;
    
    signal(SIGINT, cleanup);
    
    if (argc > 1) {
        port = atoi(argv[1]);
    }
    
    printf("========================================\n");
    printf("Linux Listener - Version 3\n");
    printf("File Browser + System Info\n");
    printf("========================================\n");
    
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("[-] Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("[-] Setsockopt failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[-] Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    
    if (listen(server_fd, 5) < 0) {
        perror("[-] Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    
    printf("[*] Listener started on 0.0.0.0:%d\n", port);
    printf("[*] Waiting for connections...\n\n");
    
    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        
        if (client_fd < 0) {
            perror("[-] Accept failed");
            continue;
        }
        
        handle_client(client_fd, client_addr);
        printf("\n[*] Waiting for new connection...\n\n");
    }
    
    close(server_fd);
    return 0;
}
