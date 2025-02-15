// Hooks.c
#include "Hooks.h"
#include <wdm.h>
#include "Private.h"

#pragma warning(disable:4047)
#pragma warning(disable:4024)

#pragma alloc_text(PAGE, BbUninstallNtQueryDirectoryFileHook)

IAT_HOOK_INFO NtQueryDirectoryFileHookInfo;

/// <summary>
/// Reads and parses a list of file names from a file on disk.
/// </summary>
/// <param name="ExcludeFile"></param>
/// <param name="ExcludedNames"></param>
/// <returns></returns>
NTSTATUS ReadExcludedNamesFromFile(PUNICODE_STRING ExcludeFile, PLIST_ENTRY ExcludedNames) {
	NTSTATUS status = STATUS_SUCCESS; // Initialize the status to SUCCESS
	HANDLE fileHandle = NULL; // Handle to the exclude file
	OBJECT_ATTRIBUTES objectAttributes; // Object attributes for file opening/creation
	IO_STATUS_BLOCK ioStatusBlock; // I/O status block for file operations
	PVOID buffer = NULL; // Buffer to hold the content of the file
	ULONG bufferSize = 0; // Size of the file buffer
	PEXCLUDED_NAME_ENTRY entry = NULL;  // Declare entry here

	// Initialize object attributes for the exclude file
	InitializeObjectAttributes(&objectAttributes, ExcludeFile, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	// Attempt to open the specified exclude file
	status = ZwOpenFile(&fileHandle, GENERIC_READ, &objectAttributes, &ioStatusBlock, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

	// If the file does not exist, attempt to create it
	if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
		// Attempt to create the exclude file with read/write access
		status = ZwCreateFile(&fileHandle, GENERIC_READ | GENERIC_WRITE, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

		// If the file creation was successful
		if (NT_SUCCESS(status)) {
			KdPrint(("BrandenBone: ReadExcludedNamesFromFile - Exclude file created successfully.\n"));
		}
		else {
			// Log an error message if the file creation failed
			KdPrint(("BrandenBone: ReadExcludedNamesFromFile - Failed to create exclude file, Status: 0x%x\n", status));
			return status; // Return the error status
		}
	}
	else if (!NT_SUCCESS(status)) {
		// Log an error message if opening the file failed
		KdPrint(("BrandenBone: ReadExcludedNamesFromFile - Failed to open exclude file, Status: 0x%x\n", status));
		return status; // Return the error status
	}

	// Get the size of the file
	FILE_STANDARD_INFORMATION fileStandardInfo;
	status = ZwQueryInformationFile(fileHandle, &ioStatusBlock, &fileStandardInfo, sizeof(fileStandardInfo), FileStandardInformation);
	if (!NT_SUCCESS(status)) {
		// Log an error message if getting the file size failed
		KdPrint(("BrandenBone: ReadExcludedNamesFromFile - Failed to get file size, Status: 0x%x\n", status));
		ZwClose(fileHandle); // Close the file handle
		return status; // Return the error status
	}

	//The rest of the code remains the same
	bufferSize = (ULONG)fileStandardInfo.EndOfFile.QuadPart; // Get the file size from the file information
	if (bufferSize == 0)
	{
		ZwClose(fileHandle); // Close the file handle
		return STATUS_SUCCESS; // If the file is empty, return success immediately
	}

	// Allocate a buffer to hold the file content
	buffer = ExAllocatePool2(POOL_FLAG_PAGED, bufferSize, BB_POOL_TAG);
	if (buffer == NULL) {
		// Log an error if buffer allocation fails
		KdPrint(("BrandenBone: ReadExcludedNamesFromFile - Failed to allocate buffer, Status: 0x%x\n", status));
		ZwClose(fileHandle); // Close the file handle
		return STATUS_INSUFFICIENT_RESOURCES; // Return an insufficient resources error
	}

	// Read the content of the file into the buffer
	status = ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock, buffer, bufferSize, NULL, NULL);
	ZwClose(fileHandle); // Close the file handle after reading

	if (!NT_SUCCESS(status)) {
		// Log an error if reading the file fails
		KdPrint(("BrandenBone: ReadExcludedNamesFromFile - Failed to read file, Status: 0x%x\n", status));
		ExFreePoolWithTag(buffer, BB_POOL_TAG); // Free the allocated buffer
		return status; // Return the error status
	}

	// Parse the file content and add names to the list
	PWCHAR current = (PWCHAR)buffer; // Pointer to the current position in the buffer
	PWCHAR end = (PWCHAR)((PUCHAR)buffer + bufferSize); // Pointer to the end of the buffer

	// Iterate through the buffer to process each line
	while (current < end) {
		// Find the end of the current line (newline or end of buffer)
		PWCHAR lineEnd = current;
		while (lineEnd < end && *lineEnd != L'\r' && *lineEnd != L'\n') {
			lineEnd++; // Increment until a newline character is found
		}

		// Calculate the length of the current line
		USHORT lineLength = (USHORT)((lineEnd - current) * sizeof(WCHAR));

		// Skip empty lines
		if (lineLength > 0) {
			// Allocate memory for the filename entry structure
			entry = (PEXCLUDED_NAME_ENTRY)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(EXCLUDED_NAME_ENTRY), BB_POOL_TAG);
			if (entry == NULL) {
				// Log an error if allocation fails
				KdPrint(("BrandenBone: ReadExcludedNamesFromFile - Failed to allocate entry, Status: 0x%x\n", status));
				break; // Exit the loop if allocation fails
			}

			RtlZeroMemory(entry, sizeof(EXCLUDED_NAME_ENTRY)); // Zero out the newly allocated entry

			// Initialize the UNICODE_STRING for the filename
			entry->FileName.Length = lineLength; // Set the length of the filename
			entry->FileName.MaximumLength = lineLength + sizeof(WCHAR); // Set the maximum length
			entry->FileName.Buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_PAGED, entry->FileName.MaximumLength, BB_POOL_TAG); // Allocate buffer for the filename

			if (entry->FileName.Buffer == NULL) {
				// Log an error if filename buffer allocation fails
				KdPrint(("BrandenBone: ReadExcludedNamesFromFile - Failed to allocate filename buffer, Status: 0x%x\n", status));
				ExFreePoolWithTag(entry, BB_POOL_TAG); // Free the allocated entry
				entry = NULL;  // Ensure entry is NULL to prevent double-free
				break; // Exit the loop if allocation fails
			}

			// Copy the filename from the buffer to the entry
			RtlCopyMemory(entry->FileName.Buffer, current, lineLength); // Copy the filename
			entry->FileName.Buffer[lineLength / sizeof(WCHAR)] = L'\0'; // Null-terminate the filename

			InsertTailList(ExcludedNames, &entry->Link); // Insert the entry into the list of excluded names
		}

		// Move to the next line, skipping any newline characters
		current = lineEnd;
		while (current < end && (*current == L'\r' || *current == L'\n')) {
			current++; // Increment the pointer to skip newline characters
		}
	}

	// Free the allocated buffer
	ExFreePoolWithTag(buffer, BB_POOL_TAG);

	return STATUS_SUCCESS; // Return success status
}

/// <summary>
/// Filters file information based on names.
/// </summary>
/// <param name="FileInformation"></param>
/// <param name="FileInformationClass"></param>
/// <param name="ExcludedNames"></param>
/// <returns></returns>
NTSTATUS FilterFileInformation(PVOID FileInformation, FILE_INFORMATION_CLASS FileInformationClass, PLIST_ENTRY ExcludedNames) {
	// Check for invalid parameters.  If either FileInformation or ExcludedNames is NULL, return an error.
	if (FileInformation == NULL || ExcludedNames == NULL)
		return STATUS_INVALID_PARAMETER;

	// Initialize a list entry to iterate through the ExcludedNames list.
	PLIST_ENTRY entry = ExcludedNames->Flink;
	// Initialize a boolean flag to track whether a file name is found in the excluded list.
	BOOLEAN found = FALSE;

	// Switch based on the FileInformationClass to handle different file information structures.
	switch (FileInformationClass) {
	case FileDirectoryInformation: {
		// Cast the FileInformation to the appropriate structure type.
		PFILE_DIRECTORY_INFORMATION current = (PFILE_DIRECTORY_INFORMATION)FileInformation;
		// Initialize a pointer to the previous entry to facilitate removal from the list.
		PFILE_DIRECTORY_INFORMATION prev = NULL;

		// Iterate through the list of FILE_DIRECTORY_INFORMATION entries.
		while (current) {
			// Reset the found flag for each entry.
			found = FALSE;
			// Iterate through the ExcludedNames list to check if the current file name should be excluded.
			for (entry = ExcludedNames->Flink; entry != ExcludedNames; entry = entry->Flink) {
				// Get a pointer to the EXCLUDED_NAME_ENTRY from the list entry.
				PEXCLUDED_NAME_ENTRY excludeEntry = CONTAINING_RECORD(entry, EXCLUDED_NAME_ENTRY, Link);
				// Compare the current file name with the excluded file name, ignoring case.
				if (RtlEqualUnicodeString(&current->FileName, &excludeEntry->FileName, TRUE)) {
					// Set the found flag if a match is found.
					found = TRUE;
					// Exit the inner loop since a match has been found.
					break;
				}
			}

			// If the file name was found in the excluded list.
			if (found) {
				// Remove the current entry from the list.
				if (prev) {
					// If there is a previous entry, update its NextEntryOffset to skip the current entry.
					prev->NextEntryOffset = current->NextEntryOffset;
				}
				else {
					//If there is no previous entry, update the FileInformation pointer
					FileInformation = (current->NextEntryOffset == 0) ? NULL : (PFILE_DIRECTORY_INFORMATION)((PUCHAR)current + current->NextEntryOffset);
				}

				// Save the pointer to the current entry before updating it.
				PFILE_DIRECTORY_INFORMATION toFree = current;
				// Move to the next entry, handling the case where it's the last entry (NextEntryOffset == 0).
				current = (current->NextEntryOffset == 0) ? NULL : (PFILE_DIRECTORY_INFORMATION)((PUCHAR)current + current->NextEntryOffset);

				// Free the memory of the skipped entry.
				ExFreePoolWithTag(toFree, BB_POOL_TAG);
			}
			else {
				// If the file name was not found in the excluded list, update the previous pointer to the current entry.
				prev = current;
				// Move to the next entry, handling the case where it's the last entry (NextEntryOffset == 0).
				current = (current->NextEntryOffset == 0) ? NULL : (PFILE_DIRECTORY_INFORMATION)((PUCHAR)current + current->NextEntryOffset);
			}
		}
		break;
	}

	default:
		// If the FileInformationClass is not supported, return an error.
		return STATUS_INVALID_INFO_CLASS;
	}

	// Return success if the filtering was completed without errors.
	return STATUS_SUCCESS;
}

//**
// CleanupExcludedNames frees the memory associated with a list of excluded file names.
//
// This function iterates through a list of EXCLUDED_NAME_ENTRY structures, freeing the memory
// associated with each entry.  It first frees the FileName buffer, then the entry itself.
//
// Parameters:
//   ExcludedNames - A pointer to the list head of the excluded names list (PLIST_ENTRY).
//                   This list is expected to be initialized and contain EXCLUDED_NAME_ENTRY structures.
//
// Returns:
//   VOID - This function does not return a value.
//
// Remarks:
//   - The function assumes that the FileName.Buffer field within each EXCLUDED_NAME_ENTRY
//     was allocated using ExAllocatePoolWithTag with the BB_POOL_TAG.
//   - The function assumes that the EXCLUDED_NAME_ENTRY structures themselves were allocated
//     using ExAllocatePoolWithTag with the BB_POOL_TAG.
//   - It is crucial that the ExcludedNames list is properly initialized before calling this function.
//     Otherwise, it will cause a system crash.
//   - After calling this function, the ExcludedNames list will be empty.
//
VOID CleanupExcludedNames(PLIST_ENTRY ExcludedNames) {
	// Iterate while the list is not empty
	while (!IsListEmpty(ExcludedNames)) {
		// Remove the first entry from the list
		PLIST_ENTRY entry = RemoveHeadList(ExcludedNames);

		// Get the EXCLUDED_NAME_ENTRY structure from the list entry
		PEXCLUDED_NAME_ENTRY excludeEntry = CONTAINING_RECORD(entry, EXCLUDED_NAME_ENTRY, Link);

		// Free the FileName buffer if it's not NULL
		if (excludeEntry->FileName.Buffer) {
			ExFreePoolWithTag(excludeEntry->FileName.Buffer, BB_POOL_TAG);
		}

		// Free the EXCLUDED_NAME_ENTRY structure
		ExFreePoolWithTag(excludeEntry, BB_POOL_TAG);
	}
}

/*++
Routine Description :
Initializes an IAT hook, preparing it for installation.

Arguments :
	HookInfo - A pointer to the IAT_HOOK_INFO structure to initialize.
	TargetModule - The base address of the module containing the IAT to be modified.
	TargetFunctionName - The name of the function to hook in the IAT.
	HookFunction - The address of the hooking function.

	Return Value :
NTSTATUS - STATUS_SUCCESS if the hook is successfully initialized, otherwise an error code.
--*/
NTSTATUS InitializeIATHook(
	PIAT_HOOK_INFO HookInfo,
	PVOID TargetModule,
	PCCHAR TargetFunctionName,
	ADDRESS HookFunction)
{
	NTSTATUS status = STATUS_SUCCESS;
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor;
	ULONG ImportSize;
	PIMAGE_THUNK_DATA* pFirstThunk;
	PIMAGE_THUNK_DATA pOriginalFirstThunk;
	PIMAGE_IMPORT_BY_NAME FunctionName;
	ULONG_PTR TargetModuleBase = (ULONG_PTR)TargetModule;

	if (!HookInfo || !TargetModule || !TargetFunctionName || !HookFunction)
	{
		status = STATUS_INVALID_PARAMETER;
		KdPrint(("BrandenBone: InitializeIATHook - Invalid parameter, Status: 0x%x\n", status));
		return status;
	}

	RtlSecureZeroMemory(HookInfo, sizeof(IAT_HOOK_INFO));
	HookInfo->TargetModule = TargetModule;
	HookInfo->TargetFunctionName = TargetFunctionName;
	HookInfo->HookFunction = HookFunction;
	HookInfo->Hooked = FALSE;
	KeInitializeSpinLock(&HookInfo->SpinLock);
	HookInfo->pIATEntry = NULL;

	NtHeaders = RtlImageNtHeader(TargetModule);
	if (NtHeaders == NULL)
	{
		status = STATUS_INVALID_IMAGE_FORMAT;
		KdPrint(("BrandenBone: InitializeIATHook - Invalid image format, Status: 0x%x\n", status));
		return status;
	}

	ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)RtlImageDirectoryEntryToData(
		TargetModule,
		TRUE,
		IMAGE_DIRECTORY_ENTRY_IMPORT,
		&ImportSize);

	if (ImportDescriptor == NULL)
	{
		status = STATUS_NOT_FOUND;
		KdPrint(("BrandenBone: InitializeIATHook - Import descriptor not found, Status: 0x%x\n", status));
		return status;
	}

	// Iterate through the import descriptors
	for (; ImportDescriptor->Name != 0; ImportDescriptor++)
	{
		//Cache these to avoid repeated calculations in the inner loop
		pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(TargetModuleBase + ImportDescriptor->OriginalFirstThunk);
		pFirstThunk = (PIMAGE_THUNK_DATA*)(TargetModuleBase + ImportDescriptor->FirstThunk);

		// Iterate through the thunks (imported function entries)
		for (; pOriginalFirstThunk->u1.AddressOfData != 0; pOriginalFirstThunk++, pFirstThunk++)
		{
			// Skip ordinals
			if (IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThunk->u1.Ordinal))
				continue;

			FunctionName = (PIMAGE_IMPORT_BY_NAME)(TargetModuleBase + pOriginalFirstThunk->u1.AddressOfData);
			//Early out if strings don't match
			if (FunctionName->Name[0] != TargetFunctionName[0])
				continue;

			if (strcmp(FunctionName->Name, TargetFunctionName) == 0)
			{
				HookInfo->pIATEntry = (PIMAGE_THUNK_DATA*)pFirstThunk;

				PIMAGE_THUNK_DATA64 thunkData = (PIMAGE_THUNK_DATA64)*pFirstThunk; // Dereference pFirstThunk
				ADDRESS OriginalFunctionAddress = (ADDRESS)thunkData->u1.Function;
				HookInfo->OriginalFunction = OriginalFunctionAddress;

				status = STATUS_SUCCESS;
				KdPrint(("BrandenBone: InitializeIATHook - Hook initialized successfully\n"));
				return status;
			}
		}
	}

	status = STATUS_NOT_FOUND;
	KdPrint(("BrandenBone: InitializeIATHook - Function not found in IAT, Status: 0x%x\n", status));
	return status;
}

/*++
Routine Description:
	Installs an IAT hook by overwriting the function pointer in the IAT with the address of the hook function.

Arguments:
	HookInfo - A pointer to the initialized IAT_HOOK_INFO structure.

Return Value:
	NTSTATUS - STATUS_SUCCESS if the hook is successfully installed, otherwise an error code.
--*/
NTSTATUS InstallIATHook(PIAT_HOOK_INFO HookInfo)
{
	KIRQL oldIrql;
	PMDL mdl = NULL;
	PVOID mapping = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	if (!HookInfo || !HookInfo->TargetModule || !HookInfo->HookFunction || HookInfo->Hooked || !HookInfo->pIATEntry)
	{
		status = STATUS_INVALID_PARAMETER;
		KdPrint(("BrandenBone: InstallIATHook - Invalid parameter, Status: 0x%x\n", status));
		return status;
	}

	// Protect and overwrite the IAT entry
	KeAcquireSpinLock(&HookInfo->SpinLock, &oldIrql);

	// Protect the memory
	mdl = IoAllocateMdl(HookInfo->pIATEntry, sizeof(ADDRESS), FALSE, FALSE, NULL);
	if (mdl == NULL)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		KdPrint(("BrandenBone: InstallIATHook - Insufficient resources, Status: 0x%x\n", status));
		goto Cleanup;
	}

	MmBuildMdlForNonPagedPool(mdl);

	// Get the virtual address
	mapping = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	if (!mapping)
	{
		status = STATUS_UNSUCCESSFUL;
		KdPrint(("BrandenBone: InstallIATHook - Memory mapping unsuccessful, Status: 0x%x\n", status));
		goto Cleanup;
	}

	//Copy the hook function address to IAT entry
	*(ADDRESS*)mapping = HookInfo->HookFunction;

	HookInfo->Hooked = TRUE;

Cleanup:
	if (mapping)
		MmUnmapLockedPages(mapping, mdl);

	if (mdl)
		IoFreeMdl(mdl);

	KeReleaseSpinLock(&HookInfo->SpinLock, oldIrql);

	if (NT_SUCCESS(status))
		KdPrint(("BrandenBone: InstallIATHook - Hook installed successfully\n"));
	else
		KdPrint(("BrandenBone: InstallIATHook - Hook installation failed, Status: 0x%x\n", status));

	return status;
}

/*++
Routine Description:
	Removes an IAT hook by restoring the original function pointer in the IAT.

Arguments:
	HookInfo - A pointer to the initialized IAT_HOOK_INFO structure.

Return Value:
	NTSTATUS - STATUS_SUCCESS if the hook is successfully removed, otherwise an error code.
--*/
NTSTATUS RemoveIATHook(PIAT_HOOK_INFO HookInfo)
{
	KIRQL oldIrql;
	PMDL mdl = NULL;
	PVOID mapping = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	if (!HookInfo || !HookInfo->TargetModule || !HookInfo->Hooked || !HookInfo->pIATEntry)
	{
		status = STATUS_INVALID_PARAMETER;
		KdPrint(("BrandenBone: RemoveIATHook - Invalid parameter, Status: 0x%x\n", status));
		return status;
	}

	KeAcquireSpinLock(&HookInfo->SpinLock, &oldIrql);

	// Protect the memory
	mdl = IoAllocateMdl(HookInfo->pIATEntry, sizeof(ADDRESS), FALSE, FALSE, NULL);
	if (mdl == NULL)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		KdPrint(("BrandenBone: RemoveIATHook - Insufficient resources, Status: 0x%x\n", status));
		goto Cleanup;
	}

	MmBuildMdlForNonPagedPool(mdl);

	// Get the virtual address
	mapping = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	if (!mapping)
	{
		status = STATUS_UNSUCCESSFUL;
		KdPrint(("BrandenBone: RemoveIATHook - Memory mapping unsuccessful, Status: 0x%x\n", status));
		goto Cleanup;
	}

	// Restore the original function address
	*(ADDRESS*)mapping = HookInfo->OriginalFunction;

	HookInfo->Hooked = FALSE;

Cleanup:
	if (mapping)
		MmUnmapLockedPages(mapping, mdl);

	if (mdl)
		IoFreeMdl(mdl);

	KeReleaseSpinLock(&HookInfo->SpinLock, oldIrql);

	if (NT_SUCCESS(status))
		KdPrint(("BrandenBone: RemoveIATHook - Hook removed successfully\n"));
	else
		KdPrint(("BrandenBone: RemoveIATHook - Hook removal failed, Status: 0x%x\n", status));
	return status;
}

/// <summary>
/// Hooks NtQueryDirectoryFile for the entire system.
/// </summary>
/// <param name="FileHandle"></param>
/// <param name="OPTIONAL"></param>
/// <param name="OPTIONAL"></param>
/// <param name="OPTIONAL"></param>
/// <param name="IoStatusBlock"></param>
/// <param name="FileInformation"></param>
/// <param name="Length"></param>
/// <param name="FileInformationClass"></param>
/// <param name="ReturnSingleEntry"></param>
/// <param name="OPTIONAL"></param>
/// <param name="RestartScan"></param>
/// <returns></returns>
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
) {
	PHOOKED_NTQUERYDIRECTORYFILE OriginalNtQueryDirectoryFile = (PHOOKED_NTQUERYDIRECTORYFILE)NtQueryDirectoryFileHookInfo.OriginalFunction;
	NTSTATUS status;

	// 1. Call the original NtQueryDirectoryFile
	status = OriginalNtQueryDirectoryFile(
		FileHandle,
		Event,
		ApcRoutine,
		ApcContext,
		IoStatusBlock,
		FileInformation,
		Length,
		FileInformationClass,
		ReturnSingleEntry,
		FileName,
		RestartScan
	);

	if (NT_SUCCESS(status)) {
		// 2. Read excluded filenames from file (example: "C:\\exclude.txt")
		UNICODE_STRING excludeFile = RTL_CONSTANT_STRING(L"C:\\excluded_files.txt");
		LIST_ENTRY excludedNames;
		InitializeListHead(&excludedNames);

		//Implement ReadExcludedNamesFromFile (reads names from file, stores in excludedNames list)
		status = ReadExcludedNamesFromFile(&excludeFile, &excludedNames);

		if (NT_SUCCESS(status)) {
			// 3. Filter the results in FileInformation
			status = FilterFileInformation(FileInformation, FileInformationClass, &excludedNames);

			//Cleanup the excludedNames list
			CleanupExcludedNames(&excludedNames);
		}
	}

	return status;
}

/*++
Routine Description:
	Installs the NtQueryDirectoryFile hook.

Arguments:
	None.

Return Value:
	NTSTATUS - STATUS_SUCCESS if the hook is successfully installed, otherwise an error code.
--*/
NTSTATUS BbInstallNtQueryDirectoryFileHook()
{
	NTSTATUS status = InitializeIATHook(
		&NtQueryDirectoryFileHookInfo,
		GetKernelBase(NULL), // Replace with your method to get module base
		"NtQueryDirectoryFile",
		(ADDRESS)HookNtQueryDirectoryFile
	);

	if (NT_SUCCESS(status)) {
		status = InstallIATHook(&NtQueryDirectoryFileHookInfo);
		if (!NT_SUCCESS(status)) {
			KdPrint(("BrandenBone: Failed to install IAT hook, Status: 0x%x\n", status));
		}
	}
	else {
		KdPrint(("BrandenBone: Failed to initialize IAT hook, Status: 0x%x\n", status));
	}

	return status;
}

/*++
Routine Description:
	Unloads the driver and removes the NtQueryDirectoryFile hook.

Arguments:
	DriverObject - Pointer to the driver object.

Return Value:
	VOID
--*/
VOID
BbUninstallNtQueryDirectoryFileHook()
{
	NTSTATUS status = RemoveIATHook(&NtQueryDirectoryFileHookInfo);
	if (!NT_SUCCESS(status)) {
		KdPrint(("BrandenBone: Failed to remove IAT hook, Status: 0x%x\n", status));
	}
	else {
		KdPrint(("BrandenBone: NtQueryDirectoryFile hook uninstalled successfully.\n"));
	}
}