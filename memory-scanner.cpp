#include <iostream>
#include <vector>
#include <windows.h>

struct MemRegion {
    uintptr_t baseAddress;
    SIZE_T size;
};

// Function to get all readable memory regions
std::vector<MemRegion> GetMemoryRegions(HANDLE hProcess) {
    std::vector<MemRegion> regions;
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t address = 0;

    while (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE))) {
            regions.push_back({ (uintptr_t)mbi.BaseAddress, mbi.RegionSize });
        }
        address += mbi.RegionSize;
    }

    return regions;
}

int main()
{
    // Open desired process by specifying it's PID
    DWORD pid;
    std::cout << "Enter PID of application to memory scan: ";
    std::cin >> pid;

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Failed to open process. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // Search memory addresses that contain specified value
    int searchValue;
    std::cout << "Enter value to search for (int): ";
    std::cin >> searchValue;

    std::vector<uintptr_t> matches;
    auto regions = GetMemoryRegions(hProcess);

    for (auto& region : regions) {
        std::vector<char> buffer(region.size);
        SIZE_T bytesRead;
        if (ReadProcessMemory(hProcess, (LPCVOID)region.baseAddress, buffer.data(), buffer.size(), &bytesRead)) {
            for (size_t i = 0; i < bytesRead - sizeof(int); i++) {
                int* val = (int*)&buffer[i];
                if (*val == searchValue) {
                    matches.push_back(region.baseAddress + i);
                }
            }
        }
    }

    // Display found addresses
    std::cout << "Found " << matches.size() << " matches." << std::endl;
    for (size_t i = 0; i < matches.size(); i++) {
        std::cout << i << ": 0x" << std::hex << matches[i] << std::dec << std::endl;
    }
}
