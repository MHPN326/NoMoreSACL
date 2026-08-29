#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <string>
#include <windows.h>
#include <sddl.h>
#include <lm.h>
#include <iostream>
#include <vector>
#include <iomanip>
#include <ntsecapi.h>
#include "decode-uac.h"
#include "getting-dns-server.h"
#include "domainsid.h"
#include "printlogonhours.h"
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")