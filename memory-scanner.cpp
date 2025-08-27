#include <iostream>
#include <vector>
#include <windows.h>
#include <iomanip>

struct Candidate {
    uintptr_t address;
};


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

// First scan through all memory
std::vector<Candidate> InitialScan(HANDLE hProcess, int searchValue) {
    std::vector<Candidate> matches;
    auto regions = GetMemoryRegions(hProcess);

    for (auto& region : regions) {
        std::vector<char> buffer(region.size);
        SIZE_T bytesRead;
        if (ReadProcessMemory(hProcess, (LPCVOID)region.baseAddress,
            buffer.data(), buffer.size(), &bytesRead)) {
            for (size_t i = 0; i < bytesRead - sizeof(int); i++) {
                int* val = (int*)&buffer[i];
                if (*val == searchValue) {
                    matches.push_back({ region.baseAddress + i });
                }
            }
        }
    }
    return matches;
}

// Rescan only known candidate addresses
std::vector<Candidate> Rescan(HANDLE hProcess, const std::vector<Candidate>& oldMatches, int newValue) {
    std::vector<Candidate> newMatches;

    for (auto& c : oldMatches) {
        int value = 0;
        SIZE_T bytesRead;
        if (ReadProcessMemory(hProcess, (LPCVOID)c.address, &value, sizeof(value), &bytesRead)) {
            if (value == newValue) {
                newMatches.push_back(c);
            }
        }
    }

    return newMatches;
}

// Displays addresses and associated values in a numbered list
void PrintMatches(HANDLE hProcess, const std::vector<Candidate>& matches) {
    std::cout << "--------------------------------------\n";
    for (size_t i = 0; i < matches.size(); i++) {
        int value = 0;
        SIZE_T bytesRead;
        ReadProcessMemory(hProcess, (LPCVOID)matches[i].address, &value, sizeof(value), &bytesRead);
        std::cout << std::setw(3) << i
            << " | Addr: 0x" << std::hex << matches[i].address << std::dec
            << " | Value: " << value << "\n";
    }
    std::cout << "--------------------------------------\n";
}

void WriteToAddress(HANDLE hProcess, LPVOID address, int newValue) {
    SIZE_T bytesWritten;
    if (WriteProcessMemory(hProcess, address, &newValue, sizeof(newValue), &bytesWritten)) {
        std::cout << "Value updated successfully!" << std::endl;
    }
    else {
        std::cerr << "Failed to write memory. Error: " << GetLastError() << std::endl;
    }
}

int main()
{
    // Open desired process by specifying it's PID
    DWORD pid;
    std::cout << "Enter PID of application to memory scan > ";
    std::cin >> pid;

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Failed to open process. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // Search for integer value
    int searchValue;
    std::cout << "Enter initial value to search for (int) > ";
    std::cin >> searchValue;

    auto matches = InitialScan(hProcess, searchValue);
    std::cout << "Initial scan found " << matches.size() << " matches." << std::endl;
    
    while (true) {
        std::cout << "[d]isplay matches; [w]rite to address; [r]escan; [q]uit > ";
        char selection;
        std::cin >> selection;

        if (selection == 'd') {
            PrintMatches(hProcess, matches);
        }
        else if (selection == 'w') {
            PrintMatches(hProcess, matches);
            
            int choice;
            std::cout << "Enter number of address to modify >";
            std::cin >> choice;
            int newVal;
            std::cout << "Enter new value >";
            std::cin >> newVal;
            
            WriteToAddress(hProcess, (LPVOID)matches[choice].address, newVal);
            PrintMatches(hProcess, matches);
        }
        else if (selection == 'r')
        {
            int newValue;
            std::cout << "Enter new value: ";
            std::cin >> newValue;

            matches = Rescan(hProcess, matches, newValue);
            std::cout << "Rescan narrowed down to " << matches.size() << " matches." << std::endl;
        }
        else if (selection == 'q') { break; }
    }
    
    CloseHandle(hProcess);
    return 0;
}
