#pragma once
#include "includes.hpp"

struct PAGE_INFO;

namespace mapping_utils
{
	uint64_t MapDriver(HANDLE iqvw64e_device_handle, HANDLE winio_handle, BYTE* data);
	void RelocateImageByDelta(portable_executable::vec_relocs relocs, const uint64_t delta);
	bool FixSecurityCookie(void* local_image, uint64_t kernel_image_base);
	bool ResolveImports(HANDLE iqvw64e_device_handle, portable_executable::vec_imports imports);
}