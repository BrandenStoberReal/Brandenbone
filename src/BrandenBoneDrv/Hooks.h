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

// Structure to hold IAT hook information
typedef struct _IAT_HOOK_INFO {
	PVOID TargetModule;         // Base address of the module containing the IAT to be hooked (e.g., kernel32.dll)
	PCCHAR TargetFunctionName;  // Name of the function to be hooked within the target module (e.g., "CreateFileW")
	ADDRESS HookFunction;       // Address of the hook function that will replace the original function
	ADDRESS OriginalFunction;   // Address of the original function (before hooking) - useful for calling the original function from the hook
	PIMAGE_THUNK_DATA* pIATEntry; // Pointer to the IAT entry that needs to be modified.  This entry contains the address of the function being hooked.
	BOOLEAN Hooked;             // Flag indicating whether the function is currently hooked (TRUE) or not (FALSE)
	KSPIN_LOCK SpinLock;        // Spin lock for synchronizing access to this IAT_HOOK_INFO structure, ensuring thread safety, especially important in kernel mode
} IAT_HOOK_INFO, * PIAT_HOOK_INFO;

/**
 * @brief Definition of a function pointer type for a hooked version of the NtQueryDirectoryFile function.
 *        This allows for intercepting and modifying the behavior of directory listing operations.
 *
 * @param FileHandle          [in] Handle to the file object representing the directory to query.
 * @param Event               [in, optional] Handle to an event to be signaled when the operation completes. Can be NULL.
 * @param ApcRoutine          [in, optional] Pointer to an APC routine to be executed upon completion. Can be NULL.
 * @param ApcContext          [in, optional] Context pointer to be passed to the APC routine. Can be NULL.
 * @param IoStatusBlock       [out] Pointer to an IO_STATUS_BLOCK structure that receives the completion status.
 * @param FileInformation     [out] Pointer to a buffer that receives the directory information.  The structure of this
 *                              buffer depends on the FileInformationClass.
 * @param Length              [in] The length, in bytes, of the FileInformation buffer.
 * @param FileInformationClass[in] Specifies the type of information to be returned in the FileInformation buffer.
 *                              This is a value from the FILE_INFORMATION_CLASS enumeration (e.g., FileDirectoryInformation,
 *                              FileNamesInformation, etc.).
 * @param ReturnSingleEntry   [in] BOOLEAN value. If TRUE, the function returns only a single entry from the directory.
 *                              If FALSE, the function returns as many entries as can fit in the FileInformation buffer.
 * @param FileName            [in, optional] Pointer to a Unicode string containing a file name within the directory.
 *                              If provided, the function will only return information about files matching this name.
 *                              Can be NULL.
 * @param RestartScan         [in] BOOLEAN value. If TRUE, the directory scan starts from the beginning. If FALSE,
 *                              the scan resumes from the previous call.
 *
 * @return NTSTATUS          NTSTATUS code indicating the success or failure of the operation.
 *
 * @remarks This typedef is intended for use in hooking the NtQueryDirectoryFile system call, allowing a driver or
 *          other system component to intercept and potentially modify the results of directory queries.  Care
 *          must be taken when using this to avoid destabilizing the system.
 */
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

/**
 * @brief Defines a structure for entries in the excluded names list.
 *
 * This structure is used to store information about file names that should be excluded
 * from a particular operation, such as scanning or processing.  It includes a doubly-linked
 * list entry for managing the list and a Unicode string to hold the file name.
 */
typedef struct _EXCLUDED_NAME_ENTRY {
	/**
	 * @brief Doubly-linked list entry.
	 *
	 * Used to link this entry into a list of excluded names.  Allows for easy
	 * insertion and removal of entries from the list.
	 */
	LIST_ENTRY Link;
	/**
	 * @brief Unicode string representing the file name to exclude.
	 *
	 * Stores the file name as a Unicode string, allowing for support of a wide
	 * range of characters.  This is the name that will be checked against during
	 * the exclusion process.
	 */
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
