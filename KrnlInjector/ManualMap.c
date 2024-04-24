
#include "ManualMap.h"

#define SystemHandleInformation		0x10
#define INT_MAX						2147483647
#define EPROCESS_IMAGEFILENAME		0x5A8
#define EPROCESS_UNIQUEPID			0x440
#define OBJTYPE_PROCESS				0x7
#define HANDLE_ALL_ACCESS			0x1FFFFF

NTSTATUS ManualMap(PVOID inputBuffer, ULONG inputBufferLength, PVOID outputBuffer, ULONG outputBufferLength)
{

	
	UNREFERENCED_PARAMETER(outputBuffer);
	UNREFERENCED_PARAMETER(outputBufferLength);

	NTSTATUS status = STATUS_SUCCESS;
	
	ULONG pid = 0;
	ANSI_STRING modulePath;
	DWORD64 configFlags;
	ANSI_STRING injectorBasePath;

	// === get the path of the dll module and get the pid of the target process ===
	status = GetBufferArguments(inputBuffer, inputBufferLength, &pid, &modulePath, &configFlags); // !!!! ADD READING BASE PATH

	if (!NT_SUCCESS(status))
	{
		DbgPrint("[-] GetBufferArguments failed\n");
		return status;
	}

	DbgPrint("[*] CONFIGFLAGS: %I64u\n", configFlags);

	// === load dll bytes from modulePath into a buffer === 
	LONGLONG	moduleSize = 0;
	PVOID		moduleBytes = AllocateDLLBytes(&modulePath, &moduleSize);
	

	if (moduleBytes == NULL || moduleSize == 0)
	{
		DbgPrint("[-] AllocatingDLLBytes failed\n");
		return status;
	}
	else
	{
		DbgPrint("[*] Buffer pointer: %p\n", moduleBytes);
	}
	
	
	// check configFlags and find valid handles to target process

	if ((configFlags & CONFIG_HIJACK_HANDLE) == CONFIG_HIJACK_HANDLE)
	{
		status = FindTargetProcessHandle(&pid, &injectorBasePath);
	}
	
	// Allocate Memory for/in the process
	





	// === write directly to a processes physical memory ===

	





	status = FreeManualMap(moduleBytes);


	return status;

}


typedef NTSTATUS(NTAPI* _ZwQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);


NTSTATUS FindTargetProcessHandle(PULONG pid, PANSI_STRING injectorBasePath)
{


	NTSTATUS status = STATUS_SUCCESS;

	UNICODE_STRING zwQuerySystemInfoName;
	RtlInitUnicodeString(&zwQuerySystemInfoName, L"ZwQuerySystemInformation");

	_ZwQuerySystemInformation pZwQuerySystemInformation = (_ZwQuerySystemInformation)MmGetSystemRoutineAddress(&zwQuerySystemInfoName);

	

	if (pZwQuerySystemInformation)
	{

		ULONG returnLength = 0;
		ULONG SystemHandleInformationSize = 0;


		PSYSTEM_HANDLE_INFORMATION handleTableInformation = NULL;

		do
		{

			handleTableInformation = (PSYSTEM_HANDLE_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, SystemHandleInformationSize, 'Tag');

			if (handleTableInformation == NULL)
			{
				DbgPrint("[-] Allocating Memory failed\n");
				return STATUS_UNSUCCESSFUL;
			}

			status = pZwQuerySystemInformation(SystemHandleInformation, handleTableInformation, SystemHandleInformationSize, &returnLength);
			SystemHandleInformationSize += 10000;

			if (!NT_SUCCESS(status))
			{
				ExFreePoolWithTag(handleTableInformation, 'Tag');
			}
			
		} while (status == STATUS_INFO_LENGTH_MISMATCH && SystemHandleInformationSize <= INT_MAX);


		if (!NT_SUCCESS(status))
		{
			DbgPrint("[-] NTSTATUS value: 0x%x\n", status);
			return status;
		}
		if (SystemHandleInformationSize > INT_MAX)
		{
			DbgPrint("[-] SystemHandleINformationSize > INT_MAX\n");
			ExFreePoolWithTag(handleTableInformation, 'Tag');
			return status;
		}
		
		// Find all open handles to target program

		UNREFERENCED_PARAMETER(pid);

		for (ULONG i = 0; i < handleTableInformation->NumberOfHandles; i++)
		{
			SYSTEM_HANDLE_TABLE_ENTRY_INFO* handleInfo = &handleTableInformation->Handles[i];
			if (handleInfo->ObjectTypeIndex == OBJTYPE_PROCESS)
			{
				if (*(PULONG)((UINT_PTR)handleInfo->Object + EPROCESS_UNIQUEPID) == *pid 
					&& handleInfo->GrantedAccess == HANDLE_ALL_ACCESS
					&& handleInfo->UniqueProcessId != 4) 
				{

					
					HANDLE proxyHandle = NULL;
					OBJECT_ATTRIBUTES objAttributes;
					CLIENT_ID cid;

					cid.UniqueProcess = (HANDLE)handleInfo->UniqueProcessId; 
					cid.UniqueThread = NULL; 
					InitializeObjectAttributes(&objAttributes, NULL, 0, NULL, NULL);
					NTSTATUS handleStatus = ZwOpenProcess(&proxyHandle, PROCESS_ALL_ACCESS, &objAttributes, &cid);

					if (NT_SUCCESS(handleStatus) && proxyHandle != NULL)
					{
						
						char* imageFileName = (char*)((UINT_PTR)handleInfo->Object + EPROCESS_IMAGEFILENAME);
						
						DbgPrint("SUCCESS FOR: Handle 0x%x at 0x%p || PID: %u || ObjTypeIndx: %u || ImageFilename: %s || HandleAttr: %u || GrantedAccess %u\n", handleInfo->HandleValue, handleInfo->Object, handleInfo->UniqueProcessId, handleInfo->ObjectTypeIndex, imageFileName, handleInfo->HandleAttributes, handleInfo->GrantedAccess);


						// !!!! Map the DLL that steals the handle into the process and call it !!!!
						LONGLONG injectorBasePathSize;
						PVOID hijackHandleDLL = AllocateDLLBytes(injectorBasePath, &injectorBasePathSize);

						// allocate memory in the victim process you steal the handle from

						PVOID baseAddress;

						//ZwAllocateVirtualMemory(proxyHandle, &baseAddress, 0, )
							

					}

					//char* imageFileName = (char*)((UINT_PTR)handleInfo->Object + EPROCESS_IMAGEFILENAME);

					//DbgPrint("Handle 0x%x at 0x%p || PID: %u || ObjTypeIndx: %u || ImageFilename: %s || HandleAttr: %u || GrantedAccess %u\n", handleInfo->HandleValue, handleInfo->Object, handleInfo->UniqueProcessId, handleInfo->ObjectTypeIndex, imageFileName, handleInfo->HandleAttributes, handleInfo->GrantedAccess);
					

				}
			}
		}

		DbgPrint("[+] Finished searching\n");

		ExFreePoolWithTag(handleTableInformation, 'Tag');

	}
	else
	{

		DbgPrint("[-] Could not find System Routine ZwQuerySystemInformation\n");
		return STATUS_UNSUCCESSFUL;

	}


	return status;

}



NTSTATUS FreeManualMap(PVOID moduleBytes)
{

	NTSTATUS status = STATUS_SUCCESS;

	if (moduleBytes != NULL)
	{
		ExFreePoolWithTag(moduleBytes, 'Tag');
		DbgPrint("[+] DLLBytes freed\n");
	}

	return status;

}


PVOID AllocateDLLBytes(PANSI_STRING modulePath, PLONGLONG moduleSize)
{

	UNICODE_STRING modulePathUni;
	NTSTATUS status = STATUS_SUCCESS;

	status = RtlAnsiStringToUnicodeString(&modulePathUni, modulePath, 1);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("[-] RtlAnsiStringToUnicodeString failed\n");
		return NULL;
	}

	OBJECT_ATTRIBUTES moduleAttributes;

	DbgPrint("[*] MODULEPATH: %ws\n", modulePathUni.Buffer);
	DbgPrint("[*] MODULEPATHADDR: %p\n", modulePathUni.Buffer);


	InitializeObjectAttributes(&moduleAttributes, &modulePathUni, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	HANDLE moduleHandle;
	IO_STATUS_BLOCK ioStatusBlock;

	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		DbgPrint("[-] Current IRQL\n");
		return NULL;
	}

	status = ZwCreateFile(&moduleHandle, GENERIC_READ, &moduleAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("[-] Could not open module NTSTATUS: 0x%08X\n", status);
		return NULL;
	}

	FILE_STANDARD_INFORMATION moduleInformation = { 0 };
	status = ZwQueryInformationFile(moduleHandle, &ioStatusBlock, &moduleInformation, sizeof(moduleInformation), FileStandardInformation);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("[-] ZwQueryInformationFile failed\n");
		return NULL;
	}

	PVOID moduleBytes = ExAllocatePool2(POOL_FLAG_NON_PAGED, moduleInformation.EndOfFile.QuadPart, 'Tag');

	*moduleSize = moduleInformation.EndOfFile.QuadPart;

	if (moduleBytes != NULL)
	{
		status = ZwReadFile(moduleHandle, NULL, NULL, NULL, &ioStatusBlock, moduleBytes, moduleInformation.EndOfFile.LowPart, 0, 0);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("[-] ZwReadFile failed\n");
			return NULL;
		}
		DbgPrint("[*] Buffer pointer: %p\n", moduleBytes);
	}
	else
	{
		DbgPrint("[-] Could not allocate file bytes\n");
		return NULL;
	}

	RtlFreeUnicodeString(&modulePathUni);
	RtlFreeAnsiString(modulePath);

	return moduleBytes;

}

/*


	IMPLEMENT:
		- To receive another 64 bit integer which is there for flag purposes on the injection methods

*/

NTSTATUS GetBufferArguments(PVOID pInputBuffer, ULONG inputBufferLength, PULONG pPid, PANSI_STRING pModulePath, PDWORD64 pConfigFlags)
{

	NTSTATUS status = STATUS_SUCCESS;

	PCHAR inputBuffer = (PCHAR)pInputBuffer;

	ANSI_STRING pidString;

	USHORT modulePathLength = 0;
	USHORT pidLength = 0;

	*pPid = 0;


	while (inputBuffer[modulePathLength] != '\0' && modulePathLength < inputBufferLength) 
		modulePathLength++;

	pModulePath->Buffer = (PCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, modulePathLength, 'Tag');
	if (pModulePath->Buffer == NULL)
	{
		DbgPrint("[-] Could not allocate Buffer\n");
		return STATUS_UNSUCCESSFUL;
	}
	pModulePath->Length = modulePathLength;
	pModulePath->MaximumLength = modulePathLength;
	RtlCopyMemory(pModulePath->Buffer, inputBuffer, modulePathLength);


	while (inputBuffer[modulePathLength + 1 + pidLength] != '\0' && (modulePathLength + 1U + pidLength) < inputBufferLength)
		pidLength++;

	pidString.Buffer = (PCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, pidLength, 'Tag');
	if (pidString.Buffer == NULL)
	{
		DbgPrint("[-] Could not allocate Buffer\n");
		return STATUS_UNSUCCESSFUL;
	}
	pidString.Length = pidLength;
	pidString.MaximumLength = pidLength;
	RtlCopyMemory(pidString.Buffer, inputBuffer + modulePathLength + 1U, pidLength);


	status = RtlCharToInteger((PCSZ)pidString.Buffer, 10, pPid);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("[-] RtlCharToInteger failed\n");
		return status;
	}

	*pConfigFlags = (DWORD64)inputBuffer[modulePathLength + 1 + pidLength + 1];

	return status;

}