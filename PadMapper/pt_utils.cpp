#include "pt_utils.hpp"
#include <Windows.h>

uintptr_t pt_utils::get_vad_offset()
{

	NTSTATUS(WINAPI * RtlGetVersion)(LPOSVERSIONINFOEXW);
	OSVERSIONINFOEXW osInfo;

	*(FARPROC*)&RtlGetVersion = GetProcAddress(GetModuleHandleA("ntdll"),
		"RtlGetVersion");

	DWORD build = 0;

	if (NULL != RtlGetVersion)
	{
		osInfo.dwOSVersionInfoSize = sizeof(osInfo);
		RtlGetVersion(&osInfo);
		build = osInfo.dwBuildNumber;
	}

	uintptr_t EP_VADROOT = 0;

	switch (build)
	{
	case 22631: //WIN11
		EP_VADROOT = 0x7d8;
		break;
	case 22000: //WIN11
		EP_VADROOT = 0x7d8;
		break;
	case 19045: // WIN10_22H2
		EP_VADROOT = 0x7d8;
		break;
	case 19044: //WIN10_21H2
		EP_VADROOT = 0x7d8;
		break;
	case 19043: //WIN10_21H1
		EP_VADROOT = 0x7d8;
		break;
	case 19042: //WIN10_20H2 (might be wrong lol)
		EP_VADROOT = 0x7d8;
		break;
	case 19041: //WIN10_20H1
		EP_VADROOT = 0x7d8;
		break;
	case 18363: //WIN10_19H2
		EP_VADROOT = 0x658;
		break;
	case 18362: //WIN10_19H1
		EP_VADROOT = 0x658;
		break;
	case 17763: //WIN10_RS5
		EP_VADROOT = 0x628;
		break;
	case 17134: //WIN10_RS4
		EP_VADROOT = 0x628;
		break;
	case 16299: //WIN10_RS3
		EP_VADROOT = 0x628;
		break;
	case 15063: //WIN10_RS2
		EP_VADROOT = 0x628;
		break;
	case 14393: //WIN10_RS1
		EP_VADROOT = 0x620;
		break;
	default:
		exit(0);
		break;
	}

	return EP_VADROOT;
}

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

uintptr_t pt_utils::get_adjusted_va(BOOLEAN start, VAD_NODE vad)
{
	if (IsBadReadPtr(&vad.ulVpnInfo, sizeof(UCHAR) * 2))
		return 0;

	UCHAR byte_offset = (start ? ((UCHAR*)&vad.ulVpnInfo)[0] : ((UCHAR*)&vad.ulVpnInfo)[1]);
	DWORD64 hi_va_start = 0x100000000 * byte_offset;
	hi_va_start += start ? vad.StartingVpn : vad.EndingVpn;

	return (uintptr_t)hi_va_start;
}

void pt_utils::avl_iterate_over(HANDLE winio_handle, VAD_NODE node, EPROCESS_DATA eproc, uintptr_t dtb)
{
	DWORD64 start_va_adjusted = get_adjusted_va(TRUE, node);
	DWORD64 end_va_adjusted = get_adjusted_va(FALSE, node);

	if (start_va_adjusted && end_va_adjusted)
		forbidden_zones.push_back({ start_va_adjusted, end_va_adjusted });

	if (node.Left) {
		VAD_NODE leftNode{};
		if (winio_driver::ReadVirtualMemory(winio_handle, (uint64_t)node.Right, (uint8_t*)&leftNode, sizeof(VAD_NODE), dtb)) {
			avl_iterate_over(winio_handle, leftNode, eproc, dtb);
		}
	}

	if (node.Right) {
		VAD_NODE rightNode{};
		if (winio_driver::ReadVirtualMemory(winio_handle, (uint64_t)node.Left, (uint8_t*)&rightNode, sizeof(VAD_NODE), dtb)) {
			avl_iterate_over(winio_handle, rightNode, eproc, dtb);
		}
	}
}

void pt_utils::fill_forbidden_zones(HANDLE winio_handle, EPROCESS_DATA eproc)
{
	forbidden_zones.clear();

	PVAD_NODE lpVadRoot;
	uintptr_t EP_VADROOT = get_vad_offset();
	uintptr_t system_cr3 = drv_utils::get_system_dirbase(winio_handle);

	if (!winio_driver::ReadVirtualMemory(winio_handle, (eproc.base + EP_VADROOT), (uint8_t*)&lpVadRoot, sizeof(PVAD_NODE), system_cr3))
		return;

	VAD_NODE vad;
	if (!winio_driver::ReadVirtualMemory(winio_handle, (uint64_t)lpVadRoot, (uint8_t*)&vad, sizeof(VAD_NODE), system_cr3))
		return;

	__try
	{
		avl_iterate_over(winio_handle, vad, eproc, system_cr3);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return;
	}
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

void pt_utils::valid_pml4e(HANDLE winio, uint64_t* pml4ind, uint64_t* pdptstruct, uintptr_t dtb)
{
	// find a valid entry
	for (int i = 1; i < 256; i++)
	{
		PML4E pml4e;

		if (!winio_driver::ReadPhysicalMemory(winio, (dtb + i * sizeof(uintptr_t)), (uint8_t*)&pml4e, sizeof(pml4e)))
		{
			return;
		}

		// page backs physical memory
		if (pml4e.Present && pml4e.UserSupervisor && pml4e.ReadWrite)
		{
			bool banned = false;
			for (auto& banned_ind : banned_pml4_indices)
			{
				if (banned_ind == i)
					banned = true;
			}

			if (!banned)
			{
				*pml4ind = i;
				*pdptstruct = pml4e.PageFrameNumber * 0x1000;
				return;
			}
		}
	}
}
void pt_utils::valid_pdpte(HANDLE winio, uint64_t pdptstruct, uint64_t* pdpteind, uint64_t* pdstruct)
{
	// find a valid entry
	for (int i = 0; i < 512; i++)
	{
		PDPTE pdpte;
		if (!winio_driver::ReadPhysicalMemory(winio, (pdptstruct + i * sizeof(uintptr_t)), (uint8_t*)&pdpte, sizeof(PDPTE)))
		{
			return;
		}

		// page backs physical memory
		if (pdpte.Present && pdpte.UserSupervisor && pdpte.ReadWrite)
		{
			bool banned = false;
			for (auto& banned_ind : banned_pdpt_indices)
			{
				if (banned_ind == i)
					banned = true;
			}

			if (!banned)
			{
				*pdpteind = i;
				*pdstruct = pdpte.PageFrameNumber * 0x1000;
				return;
			}
		}
	}
}
void pt_utils::valid_pde(HANDLE winio, uint64_t pdstruct, uint64_t* pdind, uint64_t* ptstruct)
{
	// find a valid entry
	for (int i = 0; i < 512; i++)
	{
		PDE pde;
		if (!winio_driver::ReadPhysicalMemory(winio, (pdstruct + i * sizeof(uintptr_t)), (uint8_t*)&pde, sizeof(PDE)))
		{
			return;
		}

		// page backs physical memory
		if (pde.Present && pde.UserSupervisor && pde.ReadWrite)
		{
			bool banned = false;
			for (auto& banned_ind : banned_pd_indices)
			{
				if (banned_ind == i)
					banned = true;
			}

			if (!banned)
			{
				*pdind = i;
				*ptstruct = pde.PageFrameNumber * 0x1000;
				return;
			}
		}
	}
}
void pt_utils::free_pte(HANDLE winio, uint64_t ptstruct, uint64_t* ptind)
{
	// find a valid entry
	for (int i = 0; i < 512; i++)
	{
		PTE pte;
		if (!winio_driver::ReadPhysicalMemory(winio, (ptstruct + i * sizeof(uintptr_t)), (uint8_t*)&pte, sizeof(PTE)))
		{
			return;
		}

		if (!pte.Present)
		{
			bool banned = false;
			for (auto& banned_ind : banned_pt_indices)
			{
				if (banned_ind == i)
					banned = true;
			}

			if (!banned)
			{
				*ptind = i;
				return;
			}
		}
	}
}

void pt_utils::insert_cusom_pte(HANDLE intel_handle, HANDLE winio_handle, EPROCESS_DATA eproc, uintptr_t point_pa, OUT uintptr_t* local_va)
{
	fill_forbidden_zones(winio_handle, eproc);
	Log(L"[*] Added " << std::dec << forbidden_zones.size() << L" forbidden zones\n");

find_indices:
	// find a free pte and populate other indices while at it
	valid_pml4e(winio_handle, &mal_pte_ind[PML4], &mal_pte_struct[PDPT], eproc.directory_table);
	valid_pdpte(winio_handle, mal_pte_struct[PDPT], &mal_pte_ind[PDPT], &mal_pte_struct[PD]);
	valid_pde(winio_handle, mal_pte_struct[PD], &mal_pte_ind[PD], &mal_pte_struct[PT]);
	free_pte(winio_handle, mal_pte_struct[PT], &mal_pte_ind[PT]);

	uintptr_t va = generate_virtual_address(mal_pte_ind[PML4], mal_pte_ind[PDPT], mal_pte_ind[PD], mal_pte_ind[PT], 0);
	uintptr_t vad_vpn = (va & 0xFFFFFFFFFFFFF000) / 0x1000;
	for (auto& zone : forbidden_zones)
	{
		if (zone.begin <= vad_vpn && vad_vpn <= zone.end)
		{
			banned_pml4_indices.push_back(mal_pte_ind[PML4]);
			banned_pdpt_indices.push_back(mal_pte_ind[PDPT]);
			banned_pd_indices.push_back(mal_pte_ind[PD]);
			banned_pt_indices.push_back(mal_pte_ind[PT]);

			goto find_indices;
		}
	}

	uintptr_t physical = point_pa;
	mal_pte_pfn = calc_pfnpte_from_addr(physical);

	PTE mal_pte;
	mal_pte.Present = 1;
	mal_pte.ReadWrite = 1;
	mal_pte.UserSupervisor = 1;
	mal_pte.PageFrameNumber = mal_pte_pfn.pfn;
	mal_pte.ExecuteDisable = 1;
	mal_pte.Dirty = 1;
	mal_pte.Accessed = 1;
	mal_pte.PageCacheDisable = 1;

	uintptr_t mal_pte_phys = mal_pte_struct[PT] + mal_pte_ind[PT] * sizeof(uintptr_t);

	winio_driver::WritePhysicalMemory(winio_handle, mal_pte_phys, (uint8_t*)&mal_pte, sizeof(PTE));
	Log(L"[*] Inserted custom pte at index " << mal_pte_ind[PT] << L" [" << std::hex << mal_pte_phys << L"] " << std::dec << std::endl);

	if (local_va)
		*local_va = va;
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

void pt_utils::unlink_page_from_dtb(HANDLE winio_handle, EPROCESS_DATA eproc, int32_t pml4, int32_t pdpte, int32_t pde, int32_t pte)
{
	unsigned short PML4 = (unsigned short)(pml4 & 0x1FF);
	uintptr_t PML4E = 0;
	winio_driver::ReadPhysicalMemory(winio_handle, (eproc.directory_table + PML4 * sizeof(uintptr_t)), (uint8_t*)&PML4E, sizeof(PML4E));

	if (PML4E == 0)
		return;

	unsigned short DirectoryPtr = (unsigned short)(pdpte & 0x1FF);
	uintptr_t PDPTE = 0;
	winio_driver::ReadPhysicalMemory(winio_handle, ((PML4E & 0xFFFFFFFFFF000) + DirectoryPtr * sizeof(uintptr_t)), (uint8_t*)&PDPTE, sizeof(PDPTE));

	if (PDPTE == 0)
		return;

	if ((PDPTE & (1 << 7)) != 0)
	{
		return;
	}

	unsigned short Directory = (unsigned short)(pde & 0x1FF);

	uintptr_t PDE = 0;
	winio_driver::ReadPhysicalMemory(winio_handle, ((PDPTE & 0xFFFFFFFFFF000) + Directory * sizeof(uintptr_t)), (uint8_t*)&PDE, sizeof(PDE));

	if (PDE == 0)
		return;

	if ((PDE & (1 << 7)) != 0)
	{
		return;
	}

	unsigned short Table = (unsigned short)(pte & 0x1FF);
	PTE PTE;

	winio_driver::ReadPhysicalMemory(winio_handle, ((PDE & 0xFFFFFFFFFF000) + Table * sizeof(uintptr_t)), (uint8_t*)&PTE, sizeof(PTE));

	if (PTE.Value == 0)
		return;

	uintptr_t rnd_addr = (uintptr_t)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	PTE.PageFrameNumber = calc_pfnpte_from_addr(rnd_addr).pfn;

	winio_driver::WritePhysicalMemory(winio_handle, ((PDE & 0xFFFFFFFFFF000) + Table * sizeof(uintptr_t)), (uint8_t*)&PTE, sizeof(PTE));

	return;
}

int pt_utils::create_shadow_pml4(HANDLE intel_handle, HANDLE winio_handle, EPROCESS_DATA eproc, int32_t pml4, int32_t pdpte, int32_t pde, int32_t pte, int32_t pages, uint64_t* original_pml4e_pfn, uint64_t* shadow_pml4e_pfn, uintptr_t* original_ptstruct, uintptr_t* shadow_ptstruct, uintptr_t* shadow_va, PAGE_INFO page_info[3])
{
	// insert pte that points to our local pml4 so we can hide/expose the driver
	insert_cusom_pte(intel_handle, winio_handle, eproc, eproc.directory_table, shadow_va);

	ULONG_PTR pages_to_allocate = 3;
	ULONG_PTR* physical_pages = (ULONG_PTR*)HeapAlloc(GetProcessHeap(), 0, pages_to_allocate * sizeof(ULONG_PTR));

	uintptr_t physical_pages_va = allocate_nonpageable_memory(pages_to_allocate, physical_pages);

	if (!physical_pages[0] || !physical_pages[1] || !physical_pages[2])
	{
		Log(L"[-] Error allocating physical pages\n");
		return -1;
	}

	do
	{
		PML4E PML4E{};
		winio_driver::ReadPhysicalMemory(winio_handle, (eproc.directory_table + pml4 * sizeof(uintptr_t)), (uint8_t*)&PML4E, sizeof(PML4E));

		if (PML4E.Value == 0)
			return -1;

		uintptr_t new_pdpt_phys = physical_pages[0] * 0x1000;

		byte pdpt_buf[0x1000];
		winio_driver::ReadPhysicalMemory(winio_handle, PML4E.PageFrameNumber * 0x1000, pdpt_buf, 0x1000);
		winio_driver::WritePhysicalMemory(winio_handle, new_pdpt_phys, pdpt_buf, 0x1000);

		PTE_PFN pdpt_pfn = calc_pfnpte_from_addr(new_pdpt_phys);

		if (original_pml4e_pfn)
			*original_pml4e_pfn = PML4E.PageFrameNumber;

		if (shadow_pml4e_pfn)
			*shadow_pml4e_pfn = pdpt_pfn.pfn;

		// insert 2 PTEs that allow us to update our local PDPT
		insert_cusom_pte(intel_handle, winio_handle, eproc, pdpt_pfn.pfn * 0x1000, &page_info[0].shadow_va);
		insert_cusom_pte(intel_handle, winio_handle, eproc, PML4E.PageFrameNumber * 0x1000, &page_info[0].original_va);

		PML4E.PageFrameNumber = pdpt_pfn.pfn;

		winio_driver::WritePhysicalMemory(winio_handle, (eproc.directory_table + pml4 * sizeof(uintptr_t)), (uint8_t*)&PML4E, sizeof(PML4E));

		PDPTE PDPTE{};
		winio_driver::ReadPhysicalMemory(winio_handle, ((PML4E.Value & 0xFFFFFFFFFF000) + pdpte * sizeof(uintptr_t)), (uint8_t*)&PDPTE, sizeof(PDPTE));

		if (PDPTE.Value == 0)
			return -1;

		if ((PDPTE.Value & (1 << 7)) != 0)
		{
			Log("[+] Large PDPTE Page!\n");
			return 1;
		}

		uintptr_t new_pd_phys = physical_pages[1] * 0x1000;

		byte pd_buf[0x1000];
		winio_driver::ReadPhysicalMemory(winio_handle, PDPTE.PageFrameNumber * 0x1000, pd_buf, 0x1000);
		winio_driver::WritePhysicalMemory(winio_handle, new_pd_phys, pd_buf, 0x1000);

		PTE_PFN pd_pfn = calc_pfnpte_from_addr(new_pd_phys);

		PDPTE.PageFrameNumber = pd_pfn.pfn;

		page_info[0].original_table_entry = PDPTE.Value;
		page_info[0].index = pdpte;

		// insert 2 PTEs that allow us to update our local PD
		insert_cusom_pte(intel_handle, winio_handle, eproc, pd_pfn.pfn * 0x1000, &page_info[1].shadow_va);
		insert_cusom_pte(intel_handle, winio_handle, eproc, PDPTE.PageFrameNumber * 0x1000, &page_info[1].original_va);

		winio_driver::WritePhysicalMemory(winio_handle, ((PML4E.Value & 0xFFFFFFFFFF000) + pdpte * sizeof(uintptr_t)), (uint8_t*)&PDPTE, sizeof(PDPTE));

		PDE PDE{};
		winio_driver::ReadPhysicalMemory(winio_handle, ((PDPTE.Value & 0xFFFFFFFFFF000) + pde * sizeof(uintptr_t)), (uint8_t*)&PDE, sizeof(PDE));

		if (PDE.Value == 0)
			return -1;

		if ((PDE.Value & (1 << 7)) != 0)
		{
			Log("[+] Large PDE Page!\n");
			return 1;
		}

		uintptr_t new_pt_phys = physical_pages[2] * 0x1000;

		byte pt_buf[0x1000];
		winio_driver::ReadPhysicalMemory(winio_handle, PDE.PageFrameNumber * 0x1000, pt_buf, 0x1000);
		winio_driver::WritePhysicalMemory(winio_handle, new_pt_phys, pt_buf, 0x1000);

		PTE_PFN pt_pfn = calc_pfnpte_from_addr(new_pt_phys);

		if (original_ptstruct)
			*original_ptstruct = PDE.PageFrameNumber * 0x1000;
		if (shadow_ptstruct)
			*shadow_ptstruct = pt_pfn.pfn * 0x1000;

		// insert 2 PTEs that allow us to update our local PT
		insert_cusom_pte(intel_handle, winio_handle, eproc, pt_pfn.pfn * 0x1000, &page_info[2].shadow_va);
		insert_cusom_pte(intel_handle, winio_handle, eproc, PDE.PageFrameNumber * 0x1000, &page_info[2].original_va);

		PDE.PageFrameNumber = pt_pfn.pfn;

		page_info[1].original_table_entry = PDE.Value;
		page_info[1].index = pde;

		winio_driver::WritePhysicalMemory(winio_handle, ((PDPTE.Value & 0xFFFFFFFFFF000) + pde * sizeof(uintptr_t)), (uint8_t*)&PDE, sizeof(PDE));
	
		for (int i = pte; i < pte + pages; i++)
		{
			PTE PTE{};
			winio_driver::ReadPhysicalMemory(winio_handle, ((PDE.Value & 0xFFFFFFFFFF000) + i * sizeof(uintptr_t)), (uint8_t*)&PTE, sizeof(PTE));

			PTE.ExecuteDisable = 0;
			PTE.ReadWrite = 1;

			Log("[+] Patched PTE at 0x" << std::hex << ((PDE.Value & 0xFFFFFFFFFF000) + i * sizeof(uintptr_t)) << std::endl);

			winio_driver::WritePhysicalMemory(winio_handle, ((PDE.Value & 0xFFFFFFFFFF000) + i * sizeof(uintptr_t)), (uint8_t*)&PTE, sizeof(PTE));
		}
	} while (false);

	return 1;
}

void pt_utils::swap_pml4e_pfn(HANDLE winio_handle, int32_t pml4, uint64_t new_pfn)
{
	uintptr_t cr3 = drv_utils::get_system_dirbase(winio_handle);

	PML4E PML4E{};
	winio_driver::ReadPhysicalMemory(winio_handle, (cr3 + pml4 * sizeof(uintptr_t)), (uint8_t*)&PML4E, sizeof(PML4E));

	if (PML4E.Value == 0)
		return;

	PML4E.PageFrameNumber = new_pfn;

	winio_driver::WritePhysicalMemory(winio_handle, (cr3 + pml4 * sizeof(uintptr_t)), (uint8_t*)&PML4E, sizeof(PML4E));
}

void pt_utils::patch_ptes(HANDLE winio_handle, uintptr_t ptstruct, int32_t pte, int32_t pages)
{
	for (int i = pte; i < pte + pages; i++)
	{
		PTE PTE{};
		winio_driver::ReadPhysicalMemory(winio_handle, (ptstruct + i * sizeof(uintptr_t)), (uint8_t*)&PTE, sizeof(PTE));

		PTE.ExecuteDisable = 1;
		PTE.ReadWrite = 1;

		Log("[+] Patched PTE at 0x" << std::hex << (ptstruct + i * sizeof(uintptr_t)) << std::endl);

		winio_driver::WritePhysicalMemory(winio_handle, (ptstruct + i * sizeof(uintptr_t)), (uint8_t*)&PTE, sizeof(PTE));
	}
}

void pt_utils::link_pool_to_shadow_table(HANDLE intel_handle, HANDLE winio_handle, uintptr_t ptstruct, int32_t pte, int32_t pages, uintptr_t pool, PAGE_INFO& info)
{
	int page_num = 0;
	for (int i = pte; i < pte + pages; i++)
	{
		PTE PTE{};
		winio_driver::ReadPhysicalMemory(winio_handle, (ptstruct + i * sizeof(uintptr_t)), (uint8_t*)&PTE, sizeof(PTE));

		uintptr_t phys;
		intel_driver::GetPhysicalAddress(intel_handle, (pool + (page_num * 0x1000)), &phys);

		PTE.PageFrameNumber = phys / 0x1000;

		Log("[+] Linking PTE at 0x" << std::hex << (ptstruct + i * sizeof(uintptr_t)) << std::endl);
		Log("[+] New PFN 0x" << std::hex << PTE.PageFrameNumber << std::endl);

		info.original_ptes[i] = PTE.Value;

		winio_driver::WritePhysicalMemory(winio_handle, (ptstruct + i * sizeof(uintptr_t)), (uint8_t*)&PTE, sizeof(PTE));
		page_num++;
	}
}