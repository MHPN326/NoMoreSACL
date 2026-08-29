#pragma once
#include "headers.h"

inline void PrintLogonHours(PUSER_INFO_3 buf) {
    wprintf(L"    - Units Per Week:   %u\n", buf->usri3_units_per_week);

    if (buf->usri3_logon_hours == nullptr) {
        wprintf(L"    - Logon Hours:      Not specified (Allowed 24/7)\n");
        return;
    }

    PBYTE hoursBytes = buf->usri3_logon_hours;
    bool unrestricted = true;

    for (int i = 0; i < 21; i++) {
        if (hoursBytes[i] != 0xFF) {
            unrestricted = false;
            break;
        }
    }

    if (unrestricted) {
        wprintf(L"    - Logon Hours:      Allowed 24/7 (All bits set)\n");
    }
    else {
        wprintf(L"    - Logon Hours:      Custom restrictions applied (Bitmask active)\n");
        wprintf(L"    - Raw Schedule:     ");
        for (int i = 0; i < 21; i++) {
            wprintf(L"%02X ", hoursBytes[i]);
        }
        wprintf(L"\n");
    }
}