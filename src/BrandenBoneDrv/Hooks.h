// Hooks.h
#ifndef HOOKS_H
#define HOOKS_H

#include <ntifs.h>
#include <intrin.h> // For architecture-specific intrinsics
#include "Imports.h"

// Define architecture-specific types
#ifdef _WIN64
#define IMAGE_SNAP_BY_ORDINAL(Ordinal) ((Ordinal) & 0x8000000000000000)
typedef ULONGLONG ADDRESS;
typedef PIMAGE_THUNK_DATA64 PIMAGE_THUNK_DATA;
#else
#define IMAGE_SNAP_BY_ORDINAL(Ordinal) ((Ordinal) & 0x80000000)
typedef ULONG ADDRESS;
typedef PIMAGE_THUNK_DATA32 PIMAGE_THUNK_DATA;
#endif

typedef NTSTATUS(*PHOOKED_NTQUERYDIRECTORYFILE)(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN ReturnSingleEntry,
	IN PUNICODE_STRING FileName OPTIONAL,
	IN BOOLEAN RestartScan
	);

// Structure to hold IAT hook information
typedef struct _IAT_HOOK_INFO {
	PVOID TargetModule;         // Base address of the module to hook
	PCCHAR TargetFunctionName;  // Name of the function to hook
	ADDRESS HookFunction;       // Address of the hooking function
	ADDRESS OriginalFunction;   // Original function address
	PIMAGE_THUNK_DATA* pIATEntry; // Pointer to the IAT entry
	BOOLEAN Hooked;             // Flag indicating if the hook is installed
	KSPIN_LOCK SpinLock;         // Spin lock for thread safety
} IAT_HOOK_INFO, * PIAT_HOOK_INFO;

typedef struct _EXCLUDED_NAME_ENTRY {
	LIST_ENTRY Link;
	UNICODE_STRING FileName;
} EXCLUDED_NAME_ENTRY, * PEXCLUDED_NAME_ENTRY;

extern IAT_HOOK_INFO NtQueryDirectoryFileHookInfo;

// Function prototypes
NTSTATUS ReadExcludedNamesFromFile(PUNICODE_STRING ExcludeFile, PLIST_ENTRY ExcludedNames);
NTSTATUS FilterFileInformation(PVOID FileInformation, FILE_INFORMATION_CLASS FileInformationClass, PLIST_ENTRY ExcludedNames);
VOID CleanupExcludedNames(PLIST_ENTRY ExcludedNames);
NTSTATUS InitializeIATHook(PIAT_HOOK_INFO HookInfo, PVOID TargetModule, PCCHAR TargetFunctionName, ADDRESS HookFunction);
NTSTATUS InstallIATHook(PIAT_HOOK_INFO HookInfo);
NTSTATUS RemoveIATHook(PIAT_HOOK_INFO HookInfo);
NTSTATUS NTAPI HookNtQueryDirectoryFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN ReturnSingleEntry,
	IN PUNICODE_STRING FileName OPTIONAL,
	IN BOOLEAN RestartScan
);
NTSTATUS BbInstallNtQueryDirectoryFileHook();
VOID BbUninstallNtQueryDirectoryFileHook();
#endif // HOOKS_H
