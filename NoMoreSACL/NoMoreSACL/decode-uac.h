#pragma once
#include "headers.h"
inline void DecodeUAC(unsigned int uacValue) {
    std::vector<std::pair<unsigned int, std::string>> uacFlags = {
    {0x0001, "SCRIPT : A logon script will be executed"},
    {0x0002, "ACCOUNTDISABLE : The account is disabled and cannot authenticate"},
    {0x0008, "HOMEDIR_REQUIRED : A home directory is required"},
    {0x0010, "LOCKOUT : The account is currently locked out due to bad password attempts"},
    {0x0020, "PASSWD_NOTREQD : The user is not required to have a password"},
    {0x0040, "PASSWD_CANT_CHANGE : The user cannot change their own password"},
    {0x0080, "ENCRYPTED_TEXT_PWD_ALLOWED : Permits storing passwords using reversible encryption"},
    {0x0100, "TEMP_DUPLICATE_ACCOUNT : Primarily historical; denotes a user account under a primary account"},
    {0x0200, "NORMAL_ACCOUNT : Standard default flag for a typical user object"},
    {0x0800, "INTERDOMAIN_TRUST_ACCOUNT : Used for trust accounts connecting separate domains"},
    {0x1000, "WORKSTATION_TRUST_ACCOUNT : Computer account flag for joined client workstations"},
    {0x2000, "SERVER_TRUST_ACCOUNT : Computer account flag for domain controllers or member servers"},
    {0x10000, "DONT_EXPIRE_PASSWORD : The password never expires"},
    {0x20000, "MNS_LOGON_ACCOUNT : Legacy MNS logon account"},
    {0x40000, "SMARTCARD_REQUIRED : Forces the user to log in via a smart card"},
    {0x80000, "TRUSTED_FOR_DELEGATION : The service/account can present a stolen ticket to any resource on behalf of a user"},
    {0x100000, "NOT_DELEGATED : Enforces that Kerberos tickets originating from this account will not be forwardable"},
    {0x200000, "USE_DES_KEY_ONLY : Restricts encryption to legacy DES algorithms"},
    {0x400000, "DONT_REQ_PREAUTH : Disables Kerberos Pre-Authentication (AS-REP roasting vector)"},
    {0x800000, "PASSWORD_EXPIRED : The user's password has expired and must be changed at next logon"},
    {0x1000000, "TRUSTED_TO_AUTH_FOR_DELEGATION : Allows the service to translate user tokens for constrained delegation"},
    {0x04000000, "PARTIAL_SECRETS_ACCOUNT : Denotes a Read-Only Domain Controller (RODC)"}
    };

    std::cout << "Decoding UAC Value: 0x" << std::hex << std::uppercase << uacValue << std::nouppercase << std::dec << "\n";

    bool found = false;
    for (const auto& flag : uacFlags) {
        if ((uacValue & flag.first) == flag.first) {
            std::cout << "[+] 0x" << std::setfill('0') << std::setw(6) << std::hex << flag.first
                << " : " << flag.second << "\n";
            found = true;
        }
    }

    if (!found) {
        std::cout << "[-] No known flags identified.\n";
    }
}