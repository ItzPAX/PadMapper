#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <memory>
#include <stdint.h>

#include "winio_driver_resource.hpp"
#include "service.hpp"
#include "utils.hpp"

namespace winio_driver
{
#pragma pack(push)
#pragma pack(1)
	struct winio_mem
	{
		uint64_t size;
		uint64_t addr;
		uint64_t unk1;
		uint64_t outPtr;
		uint64_t unk2;
	};
#pragma pack(pop)

	extern char driver_name[100]; //"WinIO64.sys"
	constexpr DWORD winio_timestamp = 0x58DAB337;

	static constexpr uintptr_t IOCTL_MAPMEM = 0x80102040;
	static constexpr uintptr_t IOCTL_UNMAPMEM = 0x80102044;

	std::wstring GetDriverNameW();
	std::wstring GetDriverPath();

	bool IsRunning();
	HANDLE Load(HANDLE intel_handle);
	bool Unload(HANDLE device_handle);

	uint8_t* MapPhysicalMemory(HANDLE driver_handle, uint64_t physAddr, size_t size, winio_mem& mem);
	void UnmapPhysicalMemory(HANDLE driver_handle, winio_mem& mem);
	bool ReadPhysicalMemory(HANDLE driver_handle, uint64_t physAddress, uint8_t* buffer, size_t size);
	bool WritePhysicalMemory(HANDLE driver_handle, uint64_t physAddress, uint8_t* buffer, size_t size);

	bool ReadVirtualMemory(HANDLE driver_handle, uint64_t virtual_address, uint8_t* buffer, size_t size, uintptr_t dtb);
	bool WriteVirtualMemory(HANDLE driver_handle, uint64_t virtual_address, uint8_t* buffer, size_t size, uintptr_t dtb);
}