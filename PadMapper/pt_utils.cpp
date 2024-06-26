#include "pt_utils.hpp"
#include <Windows.h>

BOOL pt_utils::LoggedSetLockPagesPrivilege(HANDLE hProcess, BOOL bEnable)
{
	struct {
		DWORD Count;
		LUID_AND_ATTRIBUTES Privilege[1];
	} Info;

	HANDLE Token;
	BOOL Result;

	// Open the token.

	Result = OpenProcessToken(hProcess,
		TOKEN_ADJUST_PRIVILEGES,
		&Token);

	if (Result != TRUE)
	{
		return FALSE;
	}

	// Enable or disable?

	Info.Count = 1;
	if (bEnable)
	{
		Info.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else
	{
		Info.Privilege[0].Attributes = 0;
	}

	// Get the LUID.

	Result = LookupPrivilegeValue(NULL,
		SE_LOCK_MEMORY_NAME,
		&(Info.Privilege[0].Luid));

	if (Result != TRUE)
	{
		return FALSE;
	}

	// Adjust the privilege.

	Result = AdjustTokenPrivileges(Token, FALSE,
		(PTOKEN_PRIVILEGES)&Info,
		0, NULL, NULL);

	// Check the result.

	if (Result != TRUE)
	{
		return FALSE;
	}
	else
	{
		if (GetLastError() != ERROR_SUCCESS)
		{
			return FALSE;
		}
	}

	CloseHandle(Token);

	return TRUE;
}

VA pt_utils::split_virtual_address(uintptr_t _va)
{
	VA va;
	va.pml4e = (unsigned short)((_va >> 39) & 0x1FF);
	va.pdpte = (unsigned short)((_va >> 30) & 0x1FF);

	va.pde = (unsigned short)((_va >> 21) & 0x1FF);
	va.pte = (unsigned short)((_va >> 12) & 0x1FF);
	va.offset = (unsigned short)_va & ~(~0ul << PAGE_OFFSET_SIZE);

	return va;
}
uint64_t pt_utils::generate_virtual_address(uint64_t pml4, uint64_t pdpt, uint64_t pd, uint64_t pt, uint64_t offset)
{
	uint64_t virtual_address =
		(pml4 << 39) |
		(pdpt << 30) |
		(pd << 21) |
		(pt << 12) |
		offset;

	return virtual_address;
}
PTE_PFN pt_utils::calc_pfnpte_from_addr(uint64_t addr)
{
	PTE_PFN pte_pfn;
	uint64_t pfn = addr >> 12;
	pte_pfn.pfn = pfn;
	pte_pfn.offset = addr - (pfn * 0x1000);
	return pte_pfn;
}

void pt_utils::valid_pml4e(int start, HANDLE winio, uint64_t* pml4ind, uint64_t* pdptstruct, uintptr_t dtb)
{
	// find a valid entry
	for (int i = start; i < 256; i++)
	{
		PML4E pml4e;

		if (!winio_driver::ReadPhysicalMemory(winio, (dtb + i * sizeof(uintptr_t)), (uint8_t*)&pml4e, sizeof(pml4e)))
		{
			return;
		}

		// page backs physical memory
		if (pml4e.Present && !pml4e.ExecuteDisable)
		{
			*pml4ind = i;
			*pdptstruct = pml4e.PageFrameNumber * 0x1000;
			return;
		}
	}
}
void pt_utils::valid_pdpte(int start, HANDLE winio, uint64_t pdptstruct, uint64_t* pdpteind, uint64_t* pdstruct)
{
	// find a valid entry
	for (int i = start; i < 512; i++)
	{
		PDPTE pdpte;
		if (!winio_driver::ReadPhysicalMemory(winio, (pdptstruct + i * sizeof(uintptr_t)), (uint8_t*)&pdpte, sizeof(PDPTE)))
		{
			return;
		}

		// page backs physical memory
		if (pdpte.Present && !pdpte.ExecuteDisable)
		{

			*pdpteind = i;
			*pdstruct = pdpte.PageFrameNumber * 0x1000;
			return;
		}
	}
}
void pt_utils::valid_pde(int start, HANDLE winio, uint64_t pdstruct, uint64_t* pdind, uint64_t* ptstruct)
{
	// find a valid entry
	for (int i = start; i < 512; i++)
	{
		PDE pde;
		if (!winio_driver::ReadPhysicalMemory(winio, (pdstruct + i * sizeof(uintptr_t)), (uint8_t*)&pde, sizeof(PDE)))
		{
			return;
		}

		// page backs physical memory
		if (pde.Present && !pde.ExecuteDisable)
		{

			*pdind = i;
			*ptstruct = pde.PageFrameNumber * 0x1000;
			return;
		}
	}
}
void pt_utils::free_pte(int start, HANDLE winio, uint64_t ptstruct, uint64_t* ptind)
{
	// find a valid entry
	for (int i = start; i < 512; i++)
	{
		PTE pte;
		if (!winio_driver::ReadPhysicalMemory(winio, (ptstruct + i * sizeof(uintptr_t)), (uint8_t*)&pte, sizeof(PTE)))
		{
			return;
		}

		if (!pte.Present)
		{
			*ptind = i;
			return;
		}
	}
}

uintptr_t pt_utils::allocate_nonpageable_memory(uint64_t pages_to_allocate, uint64_t* pfns)
{
	if (!pfns)
	{
		Log(L"[-] Failed to allocate memory for PFN array\n");
		return -1;
	}

	if (!LoggedSetLockPagesPrivilege(GetCurrentProcess(), TRUE))
	{
		Log(L"[-] Failed to enable privilege for process, please enable them Lock pages in memory for all users\n");
		return -1;
	}

	ULONG_PTR init_pages = pages_to_allocate;
	AllocateUserPhysicalPages(GetCurrentProcess(), &pages_to_allocate, pfns);

	if (init_pages != pages_to_allocate)
	{
		Log(L"[-] Failed to allocate physical memory :(\n");
		return -1;
	}

	auto reserved_pages = VirtualAlloc(NULL, pages_to_allocate * 0x1000, MEM_RESERVE | MEM_PHYSICAL, PAGE_READWRITE);

	if (reserved_pages == NULL)
	{
		Log(L"[-] Failed to reserve memory :(\n");
		return -1;
	}

	bool res = MapUserPhysicalPages(reserved_pages, pages_to_allocate, pfns);

	if (res != TRUE)
	{
		Log(L"[-] MapUserPhysicalPages failed: " << GetLastError() << L"\n");
		return -1;
	}

	return (uintptr_t)reserved_pages;
}

bool pt_utils::find_unused_mem(HANDLE winio, int pages, uintptr_t search_start, size_t search_size, uintptr_t& pt_start, uintptr_t& va, uint64_t& pt_index)
{
	VA _va_start = split_virtual_address(search_start);
	VA _va_end = split_virtual_address(search_start + search_size);
	uintptr_t dtb = drv_utils::get_system_dirbase(winio);

	// most likely it will all be located in 1 pdpte
	PML4E pml4e;
	if (!winio_driver::ReadPhysicalMemory(winio, (dtb + _va_start.pml4e * sizeof(uintptr_t)), (uint8_t*)&pml4e, sizeof(pml4e)))
		return false;
	uintptr_t pdpt_struct = pml4e.PageFrameNumber * 0x1000;

	PDPTE pdpte;
	if (!winio_driver::ReadPhysicalMemory(winio, (pdpt_struct + _va_start.pdpte * sizeof(uintptr_t)), (uint8_t*)&pdpte, sizeof(PDPTE)))
		return false;
	uintptr_t pd_struct = pdpte.PageFrameNumber * 0x1000;

	bool is_first_run = false;
	bool is_last_run = false;
	for (int current_pde = _va_start.pde; current_pde <= _va_end.pde; current_pde++)
	{
		std::cout << "[*] Searching PDE -> " << current_pde << std::endl;
		is_last_run = (current_pde == _va_end.pde);
		is_first_run = (current_pde == _va_start.pde);

		if (is_first_run)
			continue;

		PDE pde;
		if (!winio_driver::ReadPhysicalMemory(winio, (pd_struct + current_pde * sizeof(uintptr_t)), (uint8_t*)&pde, sizeof(PDE)))
			return false;

		if (pde.PageSize || !pde.Present)
			continue;

		uintptr_t pt_struct = pde.PageFrameNumber * 0x1000;
		
		int pte_start_index = 0;
		int pte_end_index = 512;
		if (is_last_run)
			pte_end_index = _va_end.pte;
		else if (is_first_run)
			pte_start_index = _va_start.pte;

		int consecutive_free_pages = 0;
		for (int idx = pte_start_index; idx < pte_end_index; idx++)
		{
			PTE pte;
			if (!winio_driver::ReadPhysicalMemory(winio, (pt_struct + idx * sizeof(uintptr_t)), (uint8_t*)&pte, sizeof(PTE)))
				continue;

			if (pte.Present)
			{
				consecutive_free_pages = 0;
				continue;
			}
			consecutive_free_pages++;

			if (consecutive_free_pages == pages - 1)
			{
				pt_start = pt_struct;
				pt_index = idx - consecutive_free_pages + 1;
				va = generate_virtual_address(_va_start.pml4e, _va_start.pdpte, current_pde, pt_index, 0);
				va += 0xFFFF000000000000;

				std::cout << "PTSTRUCT -> " << pt_start << std::endl;
				std::cout << "PTIDX -> " << pt_index << std::endl;
				std::cout << "VA -> " << va << std::endl;

				return true;
			}
		}
	}

	return false;
}