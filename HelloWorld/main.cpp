#include "defs.h"
#include <cstdint>

PVOID get_system_module_base(const char* module_name)
{
	ULONG bytes = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, bytes, &bytes);

	if (!bytes)
		return NULL;

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x4e554c4c);

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

	if (!NT_SUCCESS(status))
		return NULL;

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
	PVOID module_base = 0, module_size = 0;

	for (ULONG i = 0; i < modules->NumberOfModules; i++)
	{
		if (strcmp((char*)module[i].FullPathName, module_name) == NULL)
		{
			module_base = module[i].ImageBase;
			module_size = (PVOID)module[i].ImageSize;
			break;
		}
	}

	if (modules)
		ExFreePoolWithTag(modules, NULL);

	if (module_base <= NULL)
		return NULL;

	return module_base;
}

PVOID get_system_module_export(const char* module_name, LPCSTR routine_name)
{
	PVOID lpModule = get_system_module_base(module_name);

	if (!lpModule)
		return NULL;

	return RtlFindExportedRoutineByName(lpModule, routine_name);
}

bool write_memory(void* address, void* buffer, size_t size)
{
	if (!RtlCopyMemory(address, buffer, size))
	{
		return false;
	}
	else
	{
		return true;
	}
}

bool write_to_read_only_memory(void* address, void* buffer, size_t size)
{
	PMDL Mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);

	if (!Mdl)
		return false;

	MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
	PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);

	write_memory(Mapping, buffer, size);

	MmUnmapLockedPages(Mapping, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);

	return true;
}

NTSTATUS hook_handler(UINT_PTR dont_use1, UINT_PTR dont_use2, PULONG32 param3)
{
	UNREFERENCED_PARAMETER(dont_use1);
	UNREFERENCED_PARAMETER(dont_use2);

	DbgPrint("[+] param3 %llx\n", *param3);

	return STATUS_SUCCESS;
}

bool call_kernel_function(void* kernel_function_address)
{
	if (!kernel_function_address)
		return false;

	PVOID* function = reinterpret_cast<PVOID*>(get_system_module_export("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtDxgkGetTrackedWorkloadStatistics"));

	if (!function)
		return false;

	// Increase the size of the orig buffer to accommodate additional instructions
	BYTE orig[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	BYTE junk_code[] = { 0x8B, 0x55, 0x00 };// MOV EDX, [EBP]
	BYTE shell_code[] = { 0x48, 0xB8 }; // mov rax
	BYTE shell_code_end[] = { 0xFF, 0xE0 }; //jmp rax

	RtlSecureZeroMemory(&orig, sizeof(orig));
	memcpy((PVOID)((ULONG_PTR)orig), &shell_code, sizeof(shell_code));
	uintptr_t hook_address = reinterpret_cast<uintptr_t>(kernel_function_address);
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code)), &hook_address, sizeof(void*));
	size_t space_between = sizeof(orig) - (sizeof(shell_code) + sizeof(void*) + sizeof(shell_code_end));
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code) + sizeof(void*)), &junk_code, sizeof(junk_code));
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(orig) - sizeof(shell_code_end)), &shell_code_end, sizeof(shell_code_end));
	write_to_read_only_memory(function, &orig, sizeof(orig));

	return true;
}

NTSTATUS CustomDriverEntry(
	_In_ PDRIVER_OBJECT  kdmapperParam1,
	_In_ PUNICODE_STRING kdmapperParam2,
	_In_ VOID* ntoskrnl
)
{
	UNREFERENCED_PARAMETER(kdmapperParam1);
	UNREFERENCED_PARAMETER(kdmapperParam2);
	
	DbgPrintEx(0, 0, "> Hello world!");

	DbgPrint("> Kernel: %p", ntoskrnl);

	//call_kernel_function(&hook_handler);
	
	PVOID* gHalDispatchTable = reinterpret_cast<PVOID*>(RtlFindExportedRoutineByName(ntoskrnl, "HalDispatchTable"));
	DbgPrint("> HalDispatchTable %llx\n", gHalDispatchTable);

	gHalDispatchTable[1] = &hook_handler;

	return 0;
}