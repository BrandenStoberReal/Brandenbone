#include "Private.h"
#include "Routines.h"
#include "Loader.h"
#include "Utils.h"
#include <Ntstrsafe.h>

#define CALL_COMPLETE   0xC0371E7E

typedef struct _INJECT_BUFFER
{
	UCHAR code[0x200];
	union
	{
		UNICODE_STRING path;
		UNICODE_STRING32 path32;
	};

	wchar_t buffer[488];
	PVOID module;
	ULONG complete;
	NTSTATUS status;
} INJECT_BUFFER, * PINJECT_BUFFER;

extern DYNAMIC_DATA dynData;

PINJECT_BUFFER BBGetWow64Code(IN PVOID LdrLoadDll, IN PUNICODE_STRING pPath);
PINJECT_BUFFER BBGetNativeCode(IN PVOID LdrLoadDll, IN PUNICODE_STRING pPath);

NTSTATUS BBApcInject(IN PINJECT_BUFFER pUserBuf, IN PEPROCESS pProcess, IN ULONG initRVA, IN PCWCHAR InitArg);

#pragma alloc_text(PAGE, BBInjectDll)
#pragma alloc_text(PAGE, BBGetWow64Code)
#pragma alloc_text(PAGE, BBGetNativeCode)
#pragma alloc_text(PAGE, BBExecuteInNewThread)
#pragma alloc_text(PAGE, BBApcInject)
#pragma alloc_text(PAGE, BBQueueUserApc)
#pragma alloc_text(PAGE, BBLookupProcessThread)

/// <summary>
/// Injects a DLL into a specified process using various techniques.
/// </summary>
/// <param name="pData">
/// A pointer to an INJECT_DLL structure containing information about the target process,
/// the DLL to inject, and the injection method to use.  This structure encapsulates
/// the PID of the target process, the full path to the DLL, the injection type (Thread, APC, or MMap),
/// and other parameters such as whether to wait for the DLL to load, whether to unlink the module from the
/// loader list, and whether to erase the PE header after injection.
/// </param>
/// <returns>
/// An NTSTATUS code indicating the success or failure of the DLL injection.
/// STATUS_SUCCESS indicates that the DLL was successfully injected. Other status codes
/// indicate specific error conditions encountered during the injection process.
/// </returns>
/// <remarks>
/// This function performs DLL injection into a target process using one of several methods:
/// <list type="bullet">
///   <item>
///     <term>IT_Thread:</term>
///     <description>Creates a new thread in the target process to load the DLL.</description>
///   </item>
///   <item>
///     <term>IT_Apc:</term>
///     <description>Uses Asynchronous Procedure Calls (APCs) to load the DLL in the context of an existing thread.</description>
///   </item>
///   <item>
///     <term>IT_MMap:</term>
///     <description>Manually maps the DLL image into the target process's memory.</description>
///   </item>
/// </list>
/// The function first retrieves the EPROCESS object for the target process. Then, depending on the injection
/// type specified in pData, it proceeds with the corresponding injection method. The function handles
/// potential errors, such as the target process terminating or failing to retrieve necessary module
/// addresses. It also includes options to disable process protection temporarily, unlink the injected
/// module from the loader list, and erase the PE header of the injected DLL to evade detection.
///
/// The function utilizes kernel-mode APIs such as PsLookupProcessByProcessId, KeStackAttachProcess,
/// and ZwCreateThreadEx to perform the injection. It also uses helper functions like BBGetUserModule,
/// BBGetModuleExport, BBExecuteInNewThread, and BBApcInject to facilitate the injection process.
/// </remarks>
NTSTATUS BBInjectDll(IN PINJECT_DLL pData)
{
	NTSTATUS status = STATUS_SUCCESS; // Initialize the status to success. This will be updated if any step fails.
	NTSTATUS threadStatus = STATUS_SUCCESS; // Initialize thread status, used when creating new threads.
	PEPROCESS pProcess = NULL; // Pointer to the target process's EPROCESS object.

	// Get the EPROCESS object for the target process based on its PID.
	status = PsLookupProcessByProcessId((HANDLE)pData->pid, &pProcess);
	if (NT_SUCCESS(status))
	{
		KAPC_STATE apc; // APC state structure for attaching to the target process.
		UNICODE_STRING ustrPath, ustrNtdll; // Unicode strings to hold the DLL path and "Ntdll.dll".
		SET_PROC_PROTECTION prot = { 0 }; // Structure to hold process protection settings.
		PVOID pNtdll = NULL; // Base address of Ntdll.dll in the target process.
		PVOID LdrLoadDll = NULL; // Address of the LdrLoadDll function in the target process.
		PVOID systemBuffer = NULL; // Buffer in system space to hold the image if manual mapping is used.
		BOOLEAN isWow64 = (PsGetProcessWow64Process(pProcess) != NULL) ? TRUE : FALSE; // Flag indicating if the target process is a WOW64 process (32-bit on 64-bit).

		// Process in signaled state, abort any operations
		if (BBCheckProcessTermination(PsGetCurrentProcess()))
		{
			DPRINT("BrandenBone: %s: Process %u is terminating. Abort\n", __FUNCTION__, pData->pid);
			if (pProcess)
				ObDereferenceObject(pProcess);

			return STATUS_PROCESS_IS_TERMINATING;
		}

		// Copy mmap image buffer to system space.
		// Buffer will be released in mapping routine automatically
		if (pData->type == IT_MMap && pData->imageBase)
		{
			__try
			{
				ProbeForRead((PVOID)pData->imageBase, pData->imageSize, 1);
				systemBuffer = ExAllocatePool2(POOL_FLAG_PAGED, pData->imageSize, BB_POOL_TAG);
				RtlCopyMemory(systemBuffer, (PVOID)pData->imageBase, pData->imageSize);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DPRINT("BrandenBone: %s: AV in user buffer: 0x%p - 0x%p\n", __FUNCTION__,
					pData->imageBase, pData->imageBase + pData->imageSize);

				if (pProcess)
					ObDereferenceObject(pProcess);

				return STATUS_INVALID_USER_BUFFER;
			}
		}

		// Attach to the target process's address space.  This is necessary to operate within its memory.
		KeStackAttachProcess(pProcess, &apc);

		// Initialize Unicode strings for the DLL path and "Ntdll.dll".
		RtlInitUnicodeString(&ustrPath, pData->FullDllPath);
		RtlInitUnicodeString(&ustrNtdll, L"Ntdll.dll");

		// Handle manual map separately
		if (pData->type == IT_MMap)
		{
			MODULE_DATA mod = { 0 };

			__try {
				status = BBMapUserImage(
					pProcess, &ustrPath, systemBuffer,
					pData->imageSize, pData->asImage, pData->flags,
					pData->initRVA, pData->initArg, &mod
				);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DPRINT("BrandenBone: %s: Fatal exception in BBMapUserImage. Exception code 0x%x\n", __FUNCTION__, GetExceptionCode());
			}

			KeUnstackDetachProcess(&apc);

			if (pProcess)
				ObDereferenceObject(pProcess);

			return status;
		}

		// Get ntdll base
		pNtdll = BBGetUserModule(pProcess, &ustrNtdll, isWow64);

		// If failed to get ntdll base, set error
		if (!pNtdll)
		{
			DPRINT("BrandenBone: %s: Failed to get Ntdll base\n", __FUNCTION__);
			status = STATUS_NOT_FOUND;
		}

		// Get LdrLoadDll address
		if (NT_SUCCESS(status))
		{
			LdrLoadDll = BBGetModuleExport(pNtdll, "LdrLoadDll", pProcess, NULL);
			if (!LdrLoadDll)
			{
				DPRINT("BrandenBone: %s: Failed to get LdrLoadDll address\n", __FUNCTION__);
				status = STATUS_NOT_FOUND;
			}
		}

		// If process is protected - temporarily disable protection
		if (PsIsProtectedProcess(pProcess))
		{
			prot.pid = pData->pid;
			prot.protection = Policy_Disable;
			prot.dynamicCode = Policy_Disable;
			prot.signature = Policy_Disable;
			BBSetProtection(&prot);
		}

		// Call LdrLoadDll
		if (NT_SUCCESS(status))
		{
			SIZE_T size = 0;
			PINJECT_BUFFER pUserBuf = isWow64 ? BBGetWow64Code(LdrLoadDll, &ustrPath) : BBGetNativeCode(LdrLoadDll, &ustrPath);

			if (pData->type == IT_Thread)
			{
				status = BBExecuteInNewThread(pUserBuf, NULL, THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER, pData->wait, &threadStatus);

				// Injection failed
				if (!NT_SUCCESS(threadStatus))
				{
					status = threadStatus;
					DPRINT("BrandenBone: %s: User thread failed with status - 0x%X\n", __FUNCTION__, status);
				}
				// Call Init routine
				else
				{
					if (pUserBuf->module != 0 && pData->initRVA != 0)
					{
						RtlCopyMemory(pUserBuf->buffer, pData->initArg, sizeof(pUserBuf->buffer));
						BBExecuteInNewThread(
							(PUCHAR)pUserBuf->module + pData->initRVA,
							pUserBuf->buffer,
							THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
							TRUE,
							&threadStatus
						);
					}
					else if (pUserBuf->module == 0)
						DPRINT("BrandenBone: %s: Module base = 0. Aborting\n", __FUNCTION__);
				}
			}
			else if (pData->type == IT_Apc)
			{
				status = BBApcInject(pUserBuf, pProcess, pData->initRVA, pData->initArg);
			}
			else
			{
				DPRINT("BrandenBone: %s: Invalid injection type specified - %d\n", __FUNCTION__, pData->type);
				status = STATUS_INVALID_PARAMETER;
			}

			// Post-inject stuff
			if (NT_SUCCESS(status))
			{
				// Unlink module
				if (pData->unlink)
					BBUnlinkFromLoader(pProcess, pUserBuf->module, isWow64);

				// Erase header
				if (pData->erasePE)
				{
					__try
					{
						PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(pUserBuf->module);
						if (pHdr)
						{
							ULONG oldProt = 0;
							size = (pHdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) ?
								((PIMAGE_NT_HEADERS32)pHdr)->OptionalHeader.SizeOfHeaders :
								pHdr->OptionalHeader.SizeOfHeaders;

							if (NT_SUCCESS(ZwProtectVirtualMemory(ZwCurrentProcess(), &pUserBuf->module, &size, PAGE_EXECUTE_READWRITE, &oldProt)))
							{
								RtlZeroMemory(pUserBuf->module, size);
								ZwProtectVirtualMemory(ZwCurrentProcess(), &pUserBuf->module, &size, oldProt, &oldProt);

								DPRINT("BrandenBone: %s: PE headers erased. \n", __FUNCTION__);
							}
						}
						else
							DPRINT("BrandenBone: %s: Failed to retrieve PE headers for image\n", __FUNCTION__);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						DPRINT("BrandenBone: %s: Exception during PE header erease: 0x%X\n", __FUNCTION__, GetExceptionCode());
					}
				}
			}

			ZwFreeVirtualMemory(ZwCurrentProcess(), &pUserBuf, &size, MEM_RELEASE);
		}

		// Restore protection
		if (prot.pid != 0)
		{
			prot.protection = Policy_Enable;
			prot.dynamicCode = Policy_Enable;
			prot.signature = Policy_Enable;
			BBSetProtection(&prot);
		}

		// Detach from the target process's address space.
		KeUnstackDetachProcess(&apc);
	}
	else
		DPRINT("BrandenBone: %s: PsLookupProcessByProcessId failed with status 0x%X\n", __FUNCTION__, status);

	// Dereference the EPROCESS object to release the reference.
	if (pProcess)
		ObDereferenceObject(pProcess);

	return status; // Return the final status of the operation.
}/// <summary>

/// <summary>
/// Builds injection code for a WoW64 (Windows 32-bit on Windows 64-bit) process.
/// This function must be executed within the context of the target process.
/// </summary>
/// <param name="LdrLoadDll">The address of the LdrLoadDll function in the target process.</param>
/// <param name="pPath">A pointer to a UNICODE_STRING structure containing the path to the DLL to be injected.</param>
/// <returns>A pointer to the allocated buffer containing the injection code.
///          This buffer must be freed using ZwFreeVirtualMemory when it is no longer needed.
///          Returns NULL if the allocation fails.</returns>
PINJECT_BUFFER BBGetWow64Code(IN PVOID LdrLoadDll, IN PUNICODE_STRING pPath)
{
	NTSTATUS status = STATUS_SUCCESS; // Initialize NTSTATUS to SUCCESS
	PINJECT_BUFFER pBuffer = NULL;    // Initialize the buffer pointer to NULL
	SIZE_T size = PAGE_SIZE;          // Set the allocation size to one page

	// Shellcode to be injected into the target process.
	// This code performs the following actions:
	// 1. Pushes the address of the module handle onto the stack.
	// 2. Pushes the address of the DLL path onto the stack.
	// 3. Pushes flags (0) for LdrLoadDll onto the stack.
	// 4. Pushes a flag indicating the path is a file path (0) onto the stack.
	// 5. Calls LdrLoadDll to load the DLL.
	// 6. Sets a completion flag to indicate that the DLL has been loaded.
	// 7. Stores the NTSTATUS return value from LdrLoadDll.
	// 8. Returns from the injected code.
	UCHAR code[] =
	{
		0x68, 0, 0, 0, 0,                       // push ModuleHandle            offset +1
		0x68, 0, 0, 0, 0,                       // push ModuleFileName          offset +6
		0x6A, 0,                                // push Flags
		0x6A, 0,                                // push PathToFile
		0xE8, 0, 0, 0, 0,                       // call LdrLoadDll              offset +15
		0xBA, 0, 0, 0, 0,                       // mov edx, COMPLETE_OFFSET     offset +20
		0xC7, 0x02, 0x7E, 0x1E, 0x37, 0xC0,     // mov [edx], CALL_COMPLETE
		0xBA, 0, 0, 0, 0,                       // mov edx, STATUS_OFFSET       offset +31
		0x89, 0x02,                             // mov [edx], eax
		0xC2, 0x04, 0x00                        // ret 4
	};

	// Allocate a page of memory in the current process with execute, read, and write permissions.
	status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &pBuffer, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NT_SUCCESS(status))
	{
		// Initialize the UNICODE_STRING32 structure within the allocated buffer.
		// This structure is used to pass the DLL path to LdrLoadDll in the target process.
		PUNICODE_STRING32 pUserPath = &pBuffer->path32;                  // Get a pointer to the UNICODE_STRING32 structure within the buffer
		pUserPath->Length = pPath->Length;                               // Set the length of the string
		pUserPath->MaximumLength = pPath->MaximumLength;                 // Set the maximum length of the string
		pUserPath->Buffer = (ULONG)(ULONG_PTR)pBuffer->buffer;           // Set the buffer pointer to the start of the buffer within the allocated page

		// Copy the DLL path from the input pPath to the buffer in the target process.
		memcpy((PVOID)pUserPath->Buffer, pPath->Buffer, pPath->Length);

		// Copy the shellcode into the allocated buffer.
		memcpy(pBuffer, code, sizeof(code));

		// Fill in the placeholders in the shellcode with the appropriate addresses.
		// These addresses are relative to the allocated buffer in the target process.
		*(ULONG*)((PUCHAR)pBuffer + 1) = (ULONG)(ULONG_PTR)&pBuffer->module;                                  // Address of module handle
		*(ULONG*)((PUCHAR)pBuffer + 6) = (ULONG)(ULONG_PTR)pUserPath;                                          // Address of the path to the DLL
		*(ULONG*)((PUCHAR)pBuffer + 15) = (ULONG)((ULONG_PTR)LdrLoadDll - ((ULONG_PTR)pBuffer + 15) - 5);  // Relative address of LdrLoadDll
		*(ULONG*)((PUCHAR)pBuffer + 20) = (ULONG)(ULONG_PTR)&pBuffer->complete;                                // Address of the completion flag
		*(ULONG*)((PUCHAR)pBuffer + 31) = (ULONG)(ULONG_PTR)&pBuffer->status;                                  // Address of the status variable

		return pBuffer; // Return the pointer to the allocated buffer containing the shellcode
	}

	UNREFERENCED_PARAMETER(pPath); // Prevent compiler warning about unused parameter
	return NULL;                   // Return NULL if allocation failed
}

/// <summary>
/// Return NULL if memory allocation failed
/// Build injection code for native x64 process
/// Must be running in target process context
/// </summary>
/// <param name="LdrLoadDll">Address of LdrLoadDll function in the target process.</param>
/// <param name="pPath">Path to the DLL to be injected, represented as a UNICODE_STRING.</param>
/// <returns>Pointer to the allocated buffer containing the injection code.
///          This buffer must be freed with ZwFreeVirtualMemory when it's no longer needed.
///          Returns NULL if memory allocation fails.</returns>
PINJECT_BUFFER BBGetNativeCode(IN PVOID LdrLoadDll, IN PUNICODE_STRING pPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	PINJECT_BUFFER pBuffer = NULL;
	SIZE_T size = PAGE_SIZE;

	// Code: x64 assembly instructions for DLL injection.
	UCHAR code[] =
	{
		0x48, 0x83, 0xEC, 0x28,                 // sub rsp, 0x28 - Allocate stack space (40 bytes)
		0x48, 0x31, 0xC9,                       // xor rcx, rcx - Zero out RCX (first argument to LdrLoadDll, reserved)
		0x48, 0x31, 0xD2,                       // xor rdx, rdx - Zero out RDX (flags argument to LdrLoadDll, reserved)
		0x49, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r8, ModuleFileName   offset +12 - Move the address of the DLL path into R8 (third argument to LdrLoadDll)
		0x49, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r9, ModuleHandle     offset +22 - Move the address of the ModuleHandle into R9 (fourth argument to LdrLoadDll)
		0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rax, LdrLoadDll      offset +32 - Move the address of LdrLoadDll into RAX
		0xFF, 0xD0,                             // call rax            - Call LdrLoadDll
		0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, COMPLETE_OFFSET offset +44 - Move address of completion flag to rdx
		0xC7, 0x02, 0x7E, 0x1E, 0x37, 0xC0,     // mov [rdx], CALL_COMPLETE   - Set completion flag
		0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, STATUS_OFFSET   offset +60 - Move address of status variable to rdx
		0x89, 0x02,                             // mov [rdx], eax            - Store the return status of LdrLoadDll
		0x48, 0x83, 0xC4, 0x28,                 // add rsp, 0x28             - Restore stack pointer
		0xC3                                    // ret                       - Return
	};

	// Allocate a page-sized buffer in the target process with execute read/write permissions.
	status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &pBuffer, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NT_SUCCESS(status))
	{
		// Initialize the UNICODE_STRING structure within the allocated buffer.
		PUNICODE_STRING pUserPath = &pBuffer->path;
		pUserPath->Length = 0;                             // Initial length is zero
		pUserPath->MaximumLength = sizeof(pBuffer->buffer); // Maximum length is the size of the buffer
		pUserPath->Buffer = pBuffer->buffer;               // Buffer points to the character array

		// Copy the DLL path from the input pPath to the newly allocated buffer.
		RtlUnicodeStringCopy(pUserPath, pPath);

		// Copy the x64 assembly code into the allocated buffer.
		memcpy(pBuffer, code, sizeof(code));

		// Fill in the address stubs within the copied code with the appropriate values.
		*(ULONGLONG*)((PUCHAR)pBuffer + 12) = (ULONGLONG)pUserPath;       // Address of the DLL path
		*(ULONGLONG*)((PUCHAR)pBuffer + 22) = (ULONGLONG)&pBuffer->module;  // Address to store the loaded module handle (output)
		*(ULONGLONG*)((PUCHAR)pBuffer + 32) = (ULONGLONG)LdrLoadDll;      // Address of LdrLoadDll
		*(ULONGLONG*)((PUCHAR)pBuffer + 44) = (ULONGLONG)&pBuffer->complete; // Address of the completion flag
		*(ULONGLONG*)((PUCHAR)pBuffer + 60) = (ULONGLONG)&pBuffer->status;   // Address to store the NTSTATUS code

		return pBuffer; // Return the pointer to the allocated buffer
	}

	UNREFERENCED_PARAMETER(pPath); // Avoid compiler warning about unused parameter in case of failure
	return NULL; // Return NULL if memory allocation failed
}

/// <summary>
/// Inject dll using APC
/// Must be running in target process context
/// </summary>
/// <param name="pUserBuf">Injcetion code</param>
/// <param name="pProcess">Target process</param>
/// <param name="initRVA">Init routine RVA</param>
/// <param name="InitArg">Init routine argument</param>
/// <returns>Status code</returns>
NTSTATUS BBApcInject(IN PINJECT_BUFFER pUserBuf, IN PEPROCESS pProcess, IN ULONG initRVA, IN PCWCHAR InitArg)
{
	NTSTATUS status = STATUS_SUCCESS;
	PETHREAD pThread = NULL;

	// Get suitable thread
	status = BBLookupProcessThread(pProcess, &pThread);

	if (NT_SUCCESS(status))
	{
		status = BBQueueUserApc(pThread, pUserBuf->code, NULL, NULL, NULL, TRUE);

		// Wait for completion
		if (NT_SUCCESS(status))
		{
			LARGE_INTEGER interval = { 0 };
			interval.QuadPart = -(5LL * 10 * 1000);

			for (ULONG i = 0; i < 10000; i++)
			{
				if (BBCheckProcessTermination(PsGetCurrentProcess()) || PsIsThreadTerminating(pThread))
				{
					status = STATUS_PROCESS_IS_TERMINATING;
					break;
				}

				if (pUserBuf->complete == CALL_COMPLETE)
					break;

				if (!NT_SUCCESS(status = KeDelayExecutionThread(KernelMode, FALSE, &interval)))
					break;
			}

			// Check LdrLoadDll status
			if (NT_SUCCESS(status))
			{
				status = pUserBuf->status;
			}
			else
				DPRINT("BrandenBone: %s: APC injection abnormal termination, status 0x%X\n", __FUNCTION__, status);

			// Call init routine
			if (NT_SUCCESS(status))
			{
				if (pUserBuf->module != 0)
				{
					if (initRVA != 0)
					{
						RtlCopyMemory((PUCHAR)pUserBuf->buffer, InitArg, sizeof(pUserBuf->buffer));
						BBQueueUserApc(pThread, (PUCHAR)pUserBuf->module + initRVA, pUserBuf->buffer, NULL, NULL, TRUE);

						// Wait some time for routine to finish
						interval.QuadPart = -(100LL * 10 * 1000);
						KeDelayExecutionThread(KernelMode, FALSE, &interval);
					}
				}
				else
					DPRINT("BrandenBone: %s: APC injection failed with unknown status\n", __FUNCTION__);
			}
			else
				DPRINT("BrandenBone: %s: APC injection failed with status 0x%X\n", __FUNCTION__, status);
		}
	}
	else
		DPRINT("BrandenBone: %s: Failed to locate thread\n", __FUNCTION__);

	if (pThread)
		ObDereferenceObject(pThread);

	return status;
}