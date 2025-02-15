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

// Example Hooked Function Signature
typedef NTSTATUS(*PHOOKED_FUNCTION)(/* arguments */);

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

// Function prototypes
NTSTATUS InitializeIATHook(PIAT_HOOK_INFO HookInfo, PVOID TargetModule, PCCHAR TargetFunctionName, ADDRESS HookFunction);
NTSTATUS InstallIATHook(PIAT_HOOK_INFO HookInfo);
NTSTATUS RemoveIATHook(PIAT_HOOK_INFO HookInfo);

#endif // HOOKS_H
