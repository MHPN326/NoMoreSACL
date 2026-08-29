#pragma once
#include "headers.h"
/*

inline bool GetDomainSid() {
    LSA_OBJECT_ATTRIBUTES objectAttributes = { 0 };
    LSA_HANDLE policyHandle = NULL;
    NTSTATUS status = LsaOpenPolicy(NULL, &objectAttributes, POLICY_VIEW_LOCAL_INFORMATION, &policyHandle);

    if (status != 0) {
        std::cerr << "[-] LsaOpenPolicy failed with NTSTATUS: 0x" << std::hex << status << "\n";
        return false;
    }

    PPOLICY_ACCOUNT_DOMAIN_INFO domainInfo = NULL;
    status = LsaQueryInformationPolicy(policyHandle, PolicyAccountDomainInformation, (PVOID*)&domainInfo);

    if (status != 0 || domainInfo == NULL || domainInfo->DomainSid == NULL) {
        std::cerr << "[-] LsaQueryInformationPolicy failed with NTSTATUS: 0x" << std::hex << status << "\n";
        LsaClose(policyHandle);
        return false;
    }

    LPWSTR sidString = NULL;
    if (ConvertSidToStringSidW(domainInfo->DomainSid, &sidString)) {
        std::wcout << L"\n[+] Successfully Retrieved Domain SID:\n";
        std::wcout << L"    SID: " << sidString << L"\n";
        LocalFree(sidString);
    }

    LsaFreeMemory(domainInfo);
    LsaClose(policyHandle);
    return true;
}*/

inline bool GetDomainSid(wchar_t* destBuffer, size_t bufferSize) {
    LSA_OBJECT_ATTRIBUTES objectAttributes = { 0 };
    LSA_HANDLE policyHandle = NULL;
    NTSTATUS status = LsaOpenPolicy(NULL, &objectAttributes, POLICY_VIEW_LOCAL_INFORMATION, &policyHandle);

    if (status != 0) return false;

    // Change from PolicyAccountDomainInformation to PolicyPrimaryDomainInformation
    PPOLICY_PRIMARY_DOMAIN_INFO primaryDomainInfo = NULL;
    status = LsaQueryInformationPolicy(policyHandle, PolicyPrimaryDomainInformation, (PVOID*)&primaryDomainInfo);

    if (status != 0 || primaryDomainInfo == NULL || primaryDomainInfo->Sid == NULL) {
        LsaClose(policyHandle);
        return false;
    }

    LPWSTR sidString = NULL;
    bool success = false;
    if (ConvertSidToStringSidW(primaryDomainInfo->Sid, &sidString)) {
        wcscpy_s(destBuffer, bufferSize, sidString);
        LocalFree(sidString);
        success = true;
    }

    LsaFreeMemory(primaryDomainInfo);
    LsaClose(policyHandle);
    return success;
}