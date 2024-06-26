#pragma once
#include <unordered_map>
#include "includes.hpp"

#define PAGE_OFFSET_SIZE 12

struct EPROCESS_DATA;

// structs
typedef struct _PML4E
{
	union
	{
		struct
		{
			ULONG64 Present : 1;              // Must be 1, region invalid if 0.
			ULONG64 ReadWrite : 1;            // If 0, writes not allowed.
			ULONG64 UserSupervisor : 1;       // If 0, user-mode accesses not allowed.
			ULONG64 PageWriteThrough : 1;     // Determines the memory type used to access PDPT.
			ULONG64 PageCacheDisable : 1;     // Determines the memory type used to access PDPT.
			ULONG64 Accessed : 1;             // If 0, this entry has not been used for translation.
			ULONG64 Ignored1 : 1;
			ULONG64 PageSize : 1;             // Must be 0 for PML4E.
			ULONG64 Ignored2 : 4;
			ULONG64 PageFrameNumber : 36;     // The page frame number of the PDPT of this PML4E.
			ULONG64 Reserved : 4;
			ULONG64 Ignored3 : 11;
			ULONG64 ExecuteDisable : 1;       // If 1, instruction fetches not allowed.
		};
		ULONG64 Value;
	};
} PML4E, * PPML4E;
typedef struct _PDPTE
{
	union
	{
		struct
		{
			ULONG64 Present : 1;              // Must be 1, region invalid if 0.
			ULONG64 ReadWrite : 1;            // If 0, writes not allowed.
			ULONG64 UserSupervisor : 1;       // If 0, user-mode accesses not allowed.
			ULONG64 PageWriteThrough : 1;     // Determines the memory type used to access PD.
			ULONG64 PageCacheDisable : 1;     // Determines the memory type used to access PD.
			ULONG64 Accessed : 1;             // If 0, this entry has not been used for translation.
			ULONG64 Ignored1 : 1;
			ULONG64 PageSize : 1;             // If 1, this entry maps a 1GB page.
			ULONG64 Ignored2 : 4;
			ULONG64 PageFrameNumber : 36;     // The page frame number of the PD of this PDPTE.
			ULONG64 Reserved : 4;
			ULONG64 Ignored3 : 11;
			ULONG64 ExecuteDisable : 1;       // If 1, instruction fetches not allowed.
		};
		ULONG64 Value;
	};
} PDPTE, * PPDPTE;
typedef struct _PDE
{
	union
	{
		struct
		{
			ULONG64 Present : 1;              // Must be 1, region invalid if 0.
			ULONG64 ReadWrite : 1;            // If 0, writes not allowed.
			ULONG64 UserSupervisor : 1;       // If 0, user-mode accesses not allowed.
			ULONG64 PageWriteThrough : 1;     // Determines the memory type used to access PT.
			ULONG64 PageCacheDisable : 1;     // Determines the memory type used to access PT.
			ULONG64 Accessed : 1;             // If 0, this entry has not been used for translation.
			ULONG64 Ignored1 : 1;
			ULONG64 PageSize : 1;             // If 1, this entry maps a 2MB page.
			ULONG64 Ignored2 : 4;
			ULONG64 PageFrameNumber : 36;     // The page frame number of the PT of this PDE.
			ULONG64 Reserved : 4;
			ULONG64 Ignored3 : 11;
			ULONG64 ExecuteDisable : 1;       // If 1, instruction fetches not allowed.
		};
		ULONG64 Value;
	};
} PDE, * PPDE;
typedef struct _PTE
{
	union
	{
		struct
		{
			ULONG64 Present : 1;              // Must be 1, region invalid if 0.
			ULONG64 ReadWrite : 1;            // If 0, writes not allowed.
			ULONG64 UserSupervisor : 1;       // If 0, user-mode accesses not allowed.
			ULONG64 PageWriteThrough : 1;     // Determines the memory type used to access the memory.
			ULONG64 PageCacheDisable : 1;     // Determines the memory type used to access the memory.
			ULONG64 Accessed : 1;             // If 0, this entry has not been used for translation.
			ULONG64 Dirty : 1;                // If 0, the memory backing this page has not been written to.
			ULONG64 PageAccessType : 1;       // Determines the memory type used to access the memory.
			ULONG64 Global : 1;                // If 1 and the PGE bit of CR4 is set, translations are global.
			ULONG64 Ignored2 : 3;
			ULONG64 PageFrameNumber : 36;     // The page frame number of the backing physical page.
			ULONG64 Reserved : 4;
			ULONG64 Ignored3 : 7;
			ULONG64 ProtectionKey : 4;         // If the PKE bit of CR4 is set, determines the protection key.
			ULONG64 ExecuteDisable : 1;       // If 1, instruction fetches not allowed.
		};
		ULONG64 Value;
	};
} PTE, * PPTE;

typedef struct VAD_NODE {
	VAD_NODE* Left;
	VAD_NODE* Right;
	VAD_NODE* Parent;
	ULONG StartingVpn;
	ULONG EndingVpn;
	ULONG ulVpnInfo;
	ULONG ReferenceCount;
	PVOID PushLock;
	ULONG u;
	ULONG u1;
	PVOID u5;
	PVOID u2;
	void* Subsection; // 0x48 - 0x50
	PVOID FirstProtoPte; // 0x50 - 0x58
	PVOID LastPte; // 0x58 - 0x60
	_LIST_ENTRY ViewLinks;
	void* VadsProcess; // 0x60 - 0x68
	PVOID u4;
	PVOID FileObject;
}VAD_NODE, * PVAD_NODE;
struct FORBIDDEN_ZONE
{
	uintptr_t begin;
	uintptr_t end;
};
enum PAGING_STAGE : int
{
	PML4,
	PDPT,
	PD,
	PT
};
struct PTE_PFN
{
	uint64_t pfn;
	uint64_t offset;
};
struct VA
{
	int32_t pml4e;
	int32_t pdpte;
	int32_t pde;
	int32_t pte;
	int32_t offset;
};
struct PAGE_INFO
{
	uintptr_t shadow_va;
	uintptr_t original_va;

	UINT64 original_table_entry;
	std::unordered_map<UINT64, UINT64> original_ptes;

	uint64_t index;
};


namespace pt_utils
{
	static uint64_t mal_pte_ind[4];
	static uint64_t mal_pte_struct[4];
	static PTE_PFN mal_pte_pfn;

	// banned indices for pte insertion
	static std::vector<int> banned_pml4_indices;
	static std::vector<int> banned_pdpt_indices;
	static std::vector<int> banned_pd_indices;
	static std::vector<int> banned_pt_indices;
	static std::vector<FORBIDDEN_ZONE> forbidden_zones;

	// stupid shit because namespaces are shit
	uintptr_t get_vad_offset();

	// AWE
	BOOL LoggedSetLockPagesPrivilege(HANDLE hProcess, BOOL bEnable);

	// working set tree
	uintptr_t get_adjusted_va(BOOLEAN start, VAD_NODE vad);
	void avl_iterate_over(HANDLE winio_handle, VAD_NODE node, EPROCESS_DATA eproc, uintptr_t dtb);
	void fill_forbidden_zones(HANDLE winio_handle, EPROCESS_DATA eproc);

	// va utilities
	VA split_virtual_address(uintptr_t _va);
	PTE_PFN calc_pfnpte_from_addr(uint64_t addr);
	uint64_t generate_virtual_address(uint64_t pml4, uint64_t pdpt, uint64_t pd, uint64_t pt, uint64_t offset);

	// pt utilities
	void valid_pml4e(HANDLE winio, uint64_t* pml4ind, uint64_t* pdptstruct, uintptr_t dtb);
	void valid_pdpte(HANDLE winio, uint64_t pdptstruct, uint64_t* pdpteind, uint64_t* pdstruct);
	void valid_pde(HANDLE winio, uint64_t pdstruct, uint64_t* pdind, uint64_t* ptstruct);
	void free_pte(HANDLE winio, uint64_t ptstruct, uint64_t* ptind);

	/*
		inserts a pte that points to a phys addr
	*/
	void insert_cusom_pte(HANDLE intel_handle, HANDLE winio_handle, EPROCESS_DATA eproc, uintptr_t point_pa, OUT uintptr_t* local_va);

	uintptr_t allocate_nonpageable_memory(uint64_t pages_to_allocate, uint64_t* pfns);

	/* 
		creates a shadow pml4 that is the same as the specified paging path 
		the new pml4 however can be modified and only affect one process
	*/
	void unlink_page_from_dtb(HANDLE winio_handle, EPROCESS_DATA eproc, int32_t pml4, int32_t pdpte, int32_t pde, int32_t pte);
	int create_shadow_pml4(HANDLE intel_handle, HANDLE winio_handle, EPROCESS_DATA eproc, int32_t pml4, int32_t pdpte, int32_t pde, int32_t pte, int32_t pages, uint64_t* original_pml4e_pfn, uint64_t* shadow_pml4e_pfn, uintptr_t* original_ptstruct, uintptr_t* shadow_ptstruct, uintptr_t* shadow_va, PAGE_INFO page_info[3]);
	void swap_pml4e_pfn(HANDLE winio_handle, int32_t pml4, uint64_t new_pfn);
	void patch_ptes(HANDLE winio_handle, uintptr_t ptstruct, int32_t pte, int32_t pages);
	void link_pool_to_shadow_table(HANDLE intel_handle, HANDLE winio_handle, uintptr_t ptstruct, int32_t pte, int32_t pages, uintptr_t pool, PAGE_INFO& info);
}