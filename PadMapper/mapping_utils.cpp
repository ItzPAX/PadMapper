#include "mapping_utils.hpp"
#include "drv_utils.hpp"

uint64_t mapping_utils::MapDriver(HANDLE iqvw64e_device_handle, HANDLE winio_handle, BYTE* data)
{
	const PIMAGE_NT_HEADERS64 nt_headers = portable_executable::GetNtHeaders(data);

	if (!nt_headers) {
		Log(L"[-] Invalid format of PE image" << std::endl);
		return 0;
	}

	if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		Log(L"[-] Image is not 64 bit" << std::endl);
		return 0;
	}

	uintptr_t system_dtb = drv_utils::get_system_dirbase(winio_handle);

	uint32_t image_size = nt_headers->OptionalHeader.SizeOfImage;
	uint32_t image_pages = std::ceil(image_size / 0x1000);

	void* local_image_base = VirtualAlloc(nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!local_image_base)
		return 0;

	DWORD TotalVirtualHeaderSize = (IMAGE_FIRST_SECTION(nt_headers))->VirtualAddress;

	uintptr_t ntoskrnl_final_section = intel_driver::FindSectionAtKernel(iqvw64e_device_handle, ".reloc", intel_driver::ntoskrnlAddr, NULL);
	uintptr_t ntoskrnl_mem_size = ntoskrnl_final_section - intel_driver::ntoskrnlAddr;

	std::cout << "start -> " << std::hex << intel_driver::ntoskrnlAddr << std::endl;
	std::cout << "end -> " << std::hex << ntoskrnl_final_section << std::endl;
	std::cout << "size -> " << std::hex << ntoskrnl_mem_size << std::endl;

	uintptr_t pt_start, va, pt_idx;
	if (!pt_utils::find_unused_mem(winio_handle, image_pages, intel_driver::ntoskrnlAddr, ntoskrnl_mem_size, pt_start, va, pt_idx))
		return 0;

	VA va_comp = pt_utils::split_virtual_address(va);

	// insert physical pages into empty pad section
	ULONG_PTR* physical_pages = (ULONG_PTR*)HeapAlloc(GetProcessHeap(), 0, image_pages * sizeof(ULONG_PTR));
	pt_utils::allocate_nonpageable_memory(image_pages, physical_pages);

	for (int i = 0; i < image_pages; i++)
	{
		PTE new_pte = {};
		new_pte.Value = 0;
		new_pte.Present = 1;
		new_pte.ReadWrite = 1;
		new_pte.PageFrameNumber = physical_pages[i];

		winio_driver::WritePhysicalMemory(winio_handle, pt_start + ((i + va_comp.pte) * sizeof(uintptr_t)), (uint8_t*)&new_pte, sizeof(new_pte));
	}
	
	system("pause");

	uintptr_t kernel_image_map_base = va;

	if (!kernel_image_map_base) {
		Log(L"[-] Failed to allocate remote image in kernel" << std::endl);

		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return 0;
	}

	do {
		Log(L"[+] Image map base has been allocated at 0x" << reinterpret_cast<void*>(kernel_image_map_base) << std::endl);

		// Copy image headers

		memcpy(local_image_base, data, nt_headers->OptionalHeader.SizeOfHeaders);

		// Copy image sections

		const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(nt_headers);

		for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
			if ((current_image_section[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
				continue;
			auto local_section = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(local_image_base) + current_image_section[i].VirtualAddress);
			memcpy(local_section, reinterpret_cast<void*>(reinterpret_cast<uint64_t>(data) + current_image_section[i].PointerToRawData), current_image_section[i].SizeOfRawData);
		}

		uint64_t realBase = kernel_image_map_base;

		// Resolve relocs and imports

		RelocateImageByDelta(portable_executable::GetRelocs(local_image_base), kernel_image_map_base - nt_headers->OptionalHeader.ImageBase);

		system("pause");

		if (!FixSecurityCookie(local_image_base, kernel_image_map_base))
		{
			Log(L"[-] Failed to fix cookie" << std::endl);
			return 0;
		}

		if (!ResolveImports(iqvw64e_device_handle, portable_executable::GetImports(local_image_base)))
		{
			Log(L"[-] Failed to resolve imports" << std::endl);
			kernel_image_map_base = realBase;
			break;
		}

		system("pause");

		// Write fixed image to kernel
		if (!intel_driver::WriteMemory(iqvw64e_device_handle, kernel_image_map_base, local_image_base, image_size))
		{
			Log(L"[-] Failed to write local image to remote image" << std::endl);
			kernel_image_map_base = realBase;
			break;
		}

		system("pause");

		// Call driver entry point
		const uint64_t address_of_entry_point = kernel_image_map_base + nt_headers->OptionalHeader.AddressOfEntryPoint;

		Log(L"[<] Calling DriverEntry 0x" << reinterpret_cast<void*>(address_of_entry_point) << std::endl);

		system("pause");

		NTSTATUS status = 0;
		if (!intel_driver::CallKernelFunction(iqvw64e_device_handle, &status, address_of_entry_point, realBase, NULL, intel_driver::ntoskrnlAddr)) {
			Log(L"[-] Failed to call driver entry" << std::endl);
			kernel_image_map_base = realBase;
			break;
		}

		Log(L"[+] DriverEntry returned 0x" << std::hex << status << std::endl);

		system("pause");

		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return realBase;
	} while (false);

	VirtualFree(local_image_base, 0, MEM_RELEASE);
	return 0;
}

void mapping_utils::RelocateImageByDelta(portable_executable::vec_relocs relocs, const uint64_t delta)
{
	for (const auto& current_reloc : relocs) {
		for (auto i = 0u; i < current_reloc.count; ++i) {
			const uint16_t type = current_reloc.item[i] >> 12;
			const uint16_t offset = current_reloc.item[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
				*reinterpret_cast<uint64_t*>(current_reloc.address + offset) += delta;
		}
	}
}
bool mapping_utils::FixSecurityCookie(void* local_image, uint64_t kernel_image_base)
{
	auto headers = portable_executable::GetNtHeaders(local_image);
	if (!headers)
		return false;

	auto load_config_directory = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
	if (!load_config_directory)
	{
		Log(L"[+] Load config directory wasn't found, probably StackCookie not defined, fix cookie skipped" << std::endl);
		return true;
	}

	auto load_config_struct = (PIMAGE_LOAD_CONFIG_DIRECTORY)((uintptr_t)local_image + load_config_directory);
	auto stack_cookie = load_config_struct->SecurityCookie;
	if (!stack_cookie)
	{
		Log(L"[+] StackCookie not defined, fix cookie skipped" << std::endl);
		return true; // as I said, it is not an error and we should allow that behavior
	}

	stack_cookie = stack_cookie - (uintptr_t)kernel_image_base + (uintptr_t)local_image; //since our local image is already relocated the base returned will be kernel address

	if (*(uintptr_t*)(stack_cookie) != 0x2B992DDFA232) {
		Log(L"[-] StackCookie already fixed!? this probably wrong" << std::endl);
		return false;
	}

	Log(L"[+] Fixing stack cookie" << std::endl);

	auto new_cookie = 0x2B992DDFA232 ^ GetCurrentProcessId() ^ GetCurrentThreadId(); // here we don't really care about the value of stack cookie, it will still works and produce nice result
	if (new_cookie == 0x2B992DDFA232)
		new_cookie = 0x2B992DDFA233;

	*(uintptr_t*)(stack_cookie) = new_cookie; // the _security_cookie_complement will be init by the driver itself if they use crt
	return true;
}
bool mapping_utils::ResolveImports(HANDLE iqvw64e_device_handle, portable_executable::vec_imports imports)
{
	for (const auto& current_import : imports) {
		ULONG64 Module = utils::GetKernelModuleAddress(current_import.module_name);
		if (!Module) {
#if !defined(DISABLE_OUTPUT)
			std::cout << "[-] Dependency " << current_import.module_name << " wasn't found" << std::endl;
#endif
			return false;
		}

		for (auto& current_function_data : current_import.function_datas) {
			uint64_t function_address = intel_driver::GetKernelModuleExport(iqvw64e_device_handle, Module, current_function_data.name);

			if (!function_address) {
				//Lets try with ntoskrnl
				if (Module != intel_driver::ntoskrnlAddr) {
					function_address = intel_driver::GetKernelModuleExport(iqvw64e_device_handle, intel_driver::ntoskrnlAddr, current_function_data.name);
					if (!function_address) {
#if !defined(DISABLE_OUTPUT)
						std::cout << "[-] Failed to resolve import " << current_function_data.name << " (" << current_import.module_name << ")" << std::endl;
#endif
						return false;
					}
				}
			}

			*current_function_data.address = function_address;
		}
	}

	return true;
}