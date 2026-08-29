#pragma once
#include "headers.h"

// Dynamically retrieve the first active system DNS server IP
inline std::string GetSystemDnsServer() {
    DWORD bufferSize = 15000;
    PIP_ADAPTER_ADDRESSES addresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);
    std::string dnsServerIp = "";

    ULONG result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, addresses, &bufferSize);
    if (result == ERROR_BUFFER_OVERFLOW) {
        free(addresses);
        addresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);
        result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, addresses, &bufferSize);
    }

    if (result == NO_ERROR) {
        PIP_ADAPTER_ADDRESSES currAddresses = addresses;
        while (currAddresses) {
            if (currAddresses->OperStatus == IfOperStatusUp) {
                PIP_ADAPTER_DNS_SERVER_ADDRESS dnsServer = currAddresses->FirstDnsServerAddress;
                if (dnsServer) {
                    sockaddr* sa = dnsServer->Address.lpSockaddr;
                    if (sa->sa_family == AF_INET) {
                        char ipStr[INET_ADDRSTRLEN] = { 0 };
                        inet_ntop(AF_INET, &(((sockaddr_in*)sa)->sin_addr), ipStr, sizeof(ipStr));
                        dnsServerIp = ipStr;
                        break; // Grab the first valid active IPv4 DNS server
                    }
                }
            }
            currAddresses = currAddresses->Next;
        }
    }

    if (addresses) {
        free(addresses);
    }
    return dnsServerIp;
}

// Perform reverse lookup using the system resolver stack
inline std::string PerformDnsLookup(const std::string& targetIp) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    sockaddr_in sa = { 0 };
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, targetIp.c_str(), &sa.sin_addr);

    char hostName[NI_MAXHOST] = { 0 };
    char service[NI_MAXSERV] = { 0 };

    int ret = getnameinfo((struct sockaddr*)&sa, sizeof(sa), hostName, sizeof(hostName), service, sizeof(service), NI_NAMEREQD);

    std::string resolvedHost = "";
    std::cout << "\n[+] Dynamic DNS Lookup for Target: " << targetIp << "\n";
    if (ret == 0) {
        resolvedHost = hostName;
        std::cout << "    Resolved Hostname: " << resolvedHost << "\n";
    }
    else {
        std::cerr << "[-] getnameinfo failed. Error: " << WSAGetLastError() << "\n";
    }

    WSACleanup();
    return resolvedHost;
}