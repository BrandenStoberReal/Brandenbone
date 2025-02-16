#include <iostream>
#include <string>
#include <stdexcept>
#include "BrandenBone/DriverControl/DriverControl.h"
#include "BrandenBone/Misc/Utils.h"

using namespace BrandenBone;

int main(int argc, char* argv[]) {
	if (argc != 3) {
		std::cerr << "Usage: Injector.exe <PID> <DLL_PATH>" << std::endl;
		return 1;
	}

	DWORD pid = std::stoul(argv[1]);
	std::wstring dllPath = Utils::AnsiToWstring(argv[2]);

	// Load the driver
	NTSTATUS status = DriverControl::Instance().EnsureLoaded();
	if (!NT_SUCCESS(status)) {
		std::cerr << "Failed to load driver. Status: 0x" << std::hex << status << std::endl;
		return 1;
	}

	// Inject the DLL
	status = DriverControl::Instance().InjectDll(pid, dllPath, IT_Thread);
	if (!NT_SUCCESS(status)) {
		std::cerr << "Failed to inject DLL. Status: 0x" << std::hex << status << std::endl;
		return 1;
	}

	std::cout << "DLL injected successfully into PID: " << pid << std::endl;
	return 0;
}