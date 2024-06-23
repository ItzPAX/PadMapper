#ifndef KDLIBMODE

#include <Windows.h>
#include <string>
#include <vector>
#include <filesystem>
#include <winnt.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

#include "includes.hpp"

HANDLE iqvw64e_device_handle;
HANDLE winio_device_handle;

int wmain(const int argc, wchar_t** argv) 
{
	LoadLibrary(L"user32.dll");

	iqvw64e_device_handle = intel_driver::Load();
	if (iqvw64e_device_handle == INVALID_HANDLE_VALUE)
	{
		system("pause");
		return -1;
	}
	
	winio_device_handle = winio_driver::Load(iqvw64e_device_handle);
	if (winio_device_handle == INVALID_HANDLE_VALUE)
	{
		system("pause");
		return -1;
	}

	std::vector<uint8_t> buf;
	utils::ReadFileToMemory(L"C:\\Users\\Admin\\Desktop\\HelloWorld.sys", &buf);
	int result = mapping_utils::MapDriver(iqvw64e_device_handle, winio_device_handle, buf.data());

	if (!intel_driver::Unload(iqvw64e_device_handle)) {
		Log(L"[-] Warning failed to fully unload vulnerable driver " << std::endl);
	}
	if (!winio_driver::Unload(winio_device_handle)) {
		Log(L"[-] Warning failed to fully unload vulnerable driver " << std::endl);
	}

	system("pause");
}

#endif