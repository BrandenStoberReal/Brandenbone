// Hooks.c
#include "Hooks.h"
#include <wdm.h>

/*++
Routine Description:
	Initializes an IAT hook, preparing it for installation.

Arguments:
	HookInfo - A pointer to the IAT_HOOK_INFO structure to initialize.
	TargetModule - The base address of the module containing the IAT to be modified.
	TargetFunctionName - The name of the function to hook in the IAT.
	HookFunction - The address of the hooking function.

Return Value:
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