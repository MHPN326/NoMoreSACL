
#include "headers.h"
int main() {
    std::string activeDns = GetSystemDnsServer();
    if (!activeDns.empty()) {
        std::cout << "[+] System Primary DNS Server: " << activeDns << "\n";
    }
    else {
        std::cerr << "[-] Could not determine system DNS server.\n";
        return 1;
    }

    PerformDnsLookup(activeDns);

    wchar_t baseSidStr[128] = { 0 };
    if (!GetDomainSid(baseSidStr, ARRAYSIZE(baseSidStr))) {
        std::cerr << "[-] Failed to fetch Domain SID dynamically. Exiting.\n";
        return 1;
    }
    std::wcout << L"[+] Dynamically Populated Domain SID: " << baseSidStr << L"\n";

    // Resolve serverName ONCE outside the loop
    std::string resolvedHost = PerformDnsLookup(activeDns);
    wchar_t serverName[256] = { 0 };
    if (!resolvedHost.empty()) {
        swprintf_s(serverName, ARRAYSIZE(serverName), L"\\\\%S", resolvedHost.c_str());
    }
    else {
        wcscpy_s(serverName, ARRAYSIZE(serverName), L"\\\\127.0.0.1");
    }

    std::wcout << L"[+] Starting RID enumeration against target: " << serverName << L"\n";

    for (DWORD rid = 0; rid <= 50000; rid++) {
        wchar_t currentSidStr[128] = { 0 };
        swprintf_s(currentSidStr, ARRAYSIZE(currentSidStr), L"%s-%u", baseSidStr, rid);

        PSID targetSid = NULL;
        if (ConvertStringSidToSidW(currentSidStr, &targetSid)) {
            wchar_t accountName[256] = { 0 };
            DWORD nameSize = ARRAYSIZE(accountName);
            wchar_t domain[256] = { 0 };
            DWORD domainSize = ARRAYSIZE(domain);
            SID_NAME_USE sidType;

            // Querying remote DC via serverName
            if (LookupAccountSidW(nullptr, targetSid, accountName, &nameSize, domain, &domainSize, &sidType)) {
                std::wcout << L"\n[!] RID " << rid << L" -> " << currentSidStr << L"\n";
                std::wcout << L"    Account: " << domain << L"\\" << accountName << L" (Type: " << sidType << L")\n";

                USER_INFO_3* buf = NULL;
                NET_API_STATUS status = NetUserGetInfo(serverName, accountName, 3, (LPBYTE*)&buf);

                if (status == NERR_Success) {
                    wprintf(L"[+] NetUserGetInfo Successfully Retrieved Attributes via SAM/NetAPI:\n");
                    wprintf(L"    - Username:        %s\n", buf->usri3_name);
                    wprintf(L"    - Full Name:       %s\n", buf->usri3_full_name);
                    wprintf(L"    - User Comment:         %s\n", buf->usri3_usr_comment);
                    wprintf(L"    - Account Comment:         %s\n", buf->usri3_comment);
                    wprintf(L"    - Primary Group:   %u\n", buf->usri3_primary_group_id);
                    wprintf(L"    - Logon Count:      %u\n", buf->usri3_num_logons);
                    //Password Hygiene
                    float pwdAgeDays = (float)buf->usri3_password_age / 86400.0f;
                    wprintf(L"    - Password Age:           %u seconds (~%.1f days since last change)\n", buf->usri3_password_age, pwdAgeDays);
                    wprintf(L"    - Bad Password Count:     %u (Consecutive failed login attempts)\n", buf->usri3_bad_pw_count);
                    wprintf(L"    - Total Successful Logons:%u\n", buf->usri3_num_logons);

                    //Timestamps
                    if (buf->usri3_last_logon == 0) {
                        wprintf(L"    - Last Successful Logon:  Never\n");
                    }
                    else {
                        time_t rawTime = static_cast<time_t>(buf->usri3_last_logon);
                        struct tm timeInfo = { 0 };
                        wchar_t dateBuffer[64] = { 0 };
                        if (localtime_s(&timeInfo, &rawTime) == 0) {
                            wcsftime(dateBuffer, ARRAYSIZE(dateBuffer), L"%Y-%m-%d %H:%M:%S", &timeInfo);
                            wprintf(L"    - Last Successful Logon:  %s (Raw: %u)\n", dateBuffer, buf->usri3_last_logon);
                        }
                        else {
                            wprintf(L"    - Last Successful Logon:  %u (Raw timestamp)\n", buf->usri3_last_logon);
                        }
                    }
                    //Expiration & Status Flags
                    if (buf->usri3_acct_expires == 0xFFFFFFFF || buf->usri3_acct_expires == 0) {
                        wprintf(L"    - Account Expiration:     Never Expires\n");
                    }
                    else {
                        wprintf(L"    - Account Expiration:     Expires at timestamp %u\n", buf->usri3_acct_expires);
                    }

                    wprintf(L"    - Password Expired Status:%u (%s)\n",
                        buf->usri3_password_expired,
                        buf->usri3_password_expired ? L"Forced reset required" : L"Active / Valid");
                

                    PrintLogonHours(buf);
                    DecodeUAC(buf->usri3_flags);
                    std::cout << "--------------------------------------\n";
                    NetApiBufferFree(buf);
                }
                else {
                    printf("[-] NetUserGetInfo failed with error code: %u (0x%X)\n", status, status);
                }
            }

            LocalFree(targetSid);
        }
    }

    return 0;
}