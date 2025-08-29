#define NOMINMAX

#include <iostream>
#include <vector>
#include <windows.h>
#include <iomanip>
#include <string>
#include <psapi.h>
#include <future>
#include <tlhelp32.h>

struct Candidate {
    uintptr_t address;
};

struct MemoryRegion {
    uintptr_t baseAddress;
    size_t size;
};

// SIMD-optimized search for 4-byte integers
std::vector<size_t> FindValueSIMD(const char* buffer, size_t size, int searchValue) {
    std::vector<size_t> positions;

    // Create SIMD register with 8 copies of search value (256-bit AVX2)
    __m256i search_vec = _mm256_set1_epi32(searchValue);

    size_t simd_end = (size - sizeof(int)) & ~31; // Align to 32-byte boundary

    // SIMD loop - process 8 integers at once
    for (size_t i = 0; i < simd_end; i += 32) {
        __m256i data = _mm256_loadu_si256((__m256i*)(buffer + i));
        __m256i cmp = _mm256_cmpeq_epi32(data, search_vec);
        int mask = _mm256_movemask_epi8(cmp);

        if (mask != 0) {
            // Check each 4-byte position in this 32-byte chunk
            for (int j = 0; j < 8; j++) {
                if (mask & (0xF << (j * 4))) {
                    int* val = (int*)(buffer + i + j * 4);
                    if (*val == searchValue) {
                        positions.push_back(i + j * 4);
                    }
                }
            }
        }
    }

    // Handle remaining bytes with scalar code
    for (size_t i = simd_end; i < size - sizeof(int); i++) {
        int* val = (int*)(buffer + i);
        if (*val == searchValue) {
            positions.push_back(i);
        }
    }

    return positions;
}

// Worker function for multithreaded scanning
std::vector<Candidate> ScanRegion(HANDLE hProcess, const MemoryRegion& region, int searchValue) {
    std::vector<Candidate> matches;

    // Skip regions too small to contain an int
    if (region.size < sizeof(int)) return matches;

    const size_t BUFFER_SIZE = 1024 * 1024; // 1MB
    // Use aligned allocation for potential SIMD benefit
    char* buffer = (char*)_aligned_malloc(BUFFER_SIZE, 32);
    if (!buffer) return matches;

    for (size_t offset = 0; offset < region.size; offset += BUFFER_SIZE) {
        size_t readSize = std::min(BUFFER_SIZE, region.size - offset);
        SIZE_T bytesRead = 0;

        if (ReadProcessMemory(hProcess,
            (LPCVOID)(region.baseAddress + offset),
            buffer, readSize, &bytesRead)) {

            // Use SIMD-optimized search
            auto positions = FindValueSIMD(buffer, bytesRead, searchValue);

            for (size_t pos : positions) {
                matches.push_back({ region.baseAddress + offset + pos });
            }
        }
    }

    _aligned_free(buffer);
    return matches;
}

// Filter memory regions to scan only relevant ones
std::vector<MemoryRegion> FilterMemoryRegions(HANDLE hProcess) {
    std::vector<MemoryRegion> regions;
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t address = 0;

    while (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi))) {
        // Only scan committed, readable/writable memory
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {

            // Skip very small regions (likely not game data)
            if (mbi.RegionSize >= 4096) {
                regions.push_back({
                    (uintptr_t)mbi.BaseAddress,
                    mbi.RegionSize
                    });
            }
        }

        address = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }

    return regions;
}

// Main optimized scanning function
std::vector<Candidate> InitialScanOptimized(HANDLE hProcess, int searchValue) {
    std::vector<Candidate> allMatches;

    // Get filtered memory regions
    auto regions = FilterMemoryRegions(hProcess);

    // Determine optimal thread count (usually CPU cores - 1)
    unsigned int threadCount = std::max(1u, std::thread::hardware_concurrency() - 1);

    // For very large memory spaces, use multithreading
    if (regions.size() > 10) {
        std::vector<std::future<std::vector<Candidate>>> futures;

        // Divide regions among threads
        size_t regionsPerThread = (regions.size() + threadCount - 1) / threadCount;

        for (unsigned int t = 0; t < threadCount; t++) {
            size_t startIdx = t * regionsPerThread;
            size_t endIdx = std::min(startIdx + regionsPerThread, regions.size());

            if (startIdx < endIdx) {
                futures.push_back(std::async(std::launch::async, [&, startIdx, endIdx]() {
                    std::vector<Candidate> threadMatches;

                    for (size_t i = startIdx; i < endIdx; i++) {
                        auto regionMatches = ScanRegion(hProcess, regions[i], searchValue);
                        threadMatches.insert(threadMatches.end(),
                            regionMatches.begin(),
                            regionMatches.end());
                    }

                    return threadMatches;
                }));
            }
        }

        // Collect results from all threads
        for (auto& future : futures) {
            auto threadMatches = future.get();
            allMatches.insert(allMatches.end(),
                threadMatches.begin(),
                threadMatches.end());
        }
    }
    else {
        // For smaller memory spaces, use single-threaded approach
        for (const auto& region : regions) {
            auto regionMatches = ScanRegion(hProcess, region, searchValue);
            allMatches.insert(allMatches.end(),
                regionMatches.begin(),
                regionMatches.end());
        }
    }

    return allMatches;
}

// Function to get all readable memory regions
std::vector<MemoryRegion> GetMemoryRegions(HANDLE hProcess) {
    std::vector<MemoryRegion> regions;
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

// OLD InitialScan without optimizations
//std::vector<Candidate> InitialScan(HANDLE hProcess, int searchValue) {
//    std::vector<Candidate> matches;
//    auto regions = GetMemoryRegions(hProcess);
//
//    for (auto& region : regions) {
//        // Skip regions too small to contain an int
//        if (region.size < sizeof(int)) continue;
//
//        std::vector<char> buffer(region.size);
//        SIZE_T bytesRead = 0;
//        if (ReadProcessMemory(hProcess, (LPCVOID)region.baseAddress,
//            buffer.data(), buffer.size(), &bytesRead)) {
//            // Use pointer arithmetic for faster scanning
//            const char* data = buffer.data();
//            size_t maxOffset = bytesRead - sizeof(int) + 1;
//            for (size_t i = 0; i < maxOffset; ++i) {
//                // Use memcpy to avoid unaligned access
//                int val;
//                memcpy(&val, data + i, sizeof(int));
//                if (val == searchValue) {
//                    matches.push_back({ region.baseAddress + i });
//                }
//            }
//        }
//    }
//    return matches;
//}

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

// Helper function to write a new value to a specific address
void WriteToAddress(HANDLE hProcess, LPVOID address, int newValue) {
    SIZE_T bytesWritten;
    if (WriteProcessMemory(hProcess, address, &newValue, sizeof(newValue), &bytesWritten)) {
        std::cout << "Value updated successfully!" << std::endl;
    }
    else {
        std::cerr << "Failed to write memory. Error: " << GetLastError() << std::endl;
    }
}

// Helper function to get process name from handle
std::string GetProcessName(HANDLE hProcess) {
    char name[MAX_PATH] = "<unknown>";
    if (GetModuleBaseNameA(hProcess, NULL, name, sizeof(name) / sizeof(char))) {
        return std::string(name);
    }
    return "<unknown>";
}

// Lists all running processes with their names and PIDs
void ListProcesses() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot.\n";
        return;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        std::cout << "PID\tProcess Name\n";
        std::cout << "-----------------------------\n";
        do {
            std::wcout << pe.th32ProcessID << "\t" << pe.szExeFile << "\n";
        } while (Process32Next(hSnapshot, &pe));
    }
    else {
        std::cerr << "Failed to enumerate processes.\n";
    }

    CloseHandle(hSnapshot);
}

//// Alternative: Pattern-based search for common game values
//std::vector<Candidate> SearchGamePatterns(HANDLE hProcess, int searchValue) {
//    std::vector<Candidate> matches;
//
//    // Common UE5 memory patterns - adjust base addresses as needed
//    std::vector<std::pair<uintptr_t, size_t>> commonRanges = {
//        {0x140000000, 0x10000000}, // Common game module range
//        {0x7FF000000000, 0x1000000000}, // User-mode address space
//    };
//
//    for (auto& range : commonRanges) {
//        MemoryRegion region = { range.first, range.second };
//        auto regionMatches = ScanRegion(hProcess, region, searchValue);
//        matches.insert(matches.end(), regionMatches.begin(), regionMatches.end());
//    }
//
//    return matches;
//}

int main()
{
    std::vector<Candidate> matches;
	int searchValue = 0;
    HANDLE hProcess = NULL;
    DWORD pid = 0;
    std::string procName = "NULL";
    
    while (true) {
        std::cout << "Attached to process: " << procName << "\n";
        std::cout << "[d]isplay matches; [f]ind processes; [w]rite to address; [r]e scan; [n]ew scan ; [m]anual address access; [q]uit > ";
        char selection;
        std::cin >> selection;

        if (selection == 'd') {
            if (matches.empty()) {
                std::cout << "No matches to display. Perform a scan first." << std::endl;
                continue;
			}
            PrintMatches(hProcess, matches);
        }
        else if (selection == 'f') {
            ListProcesses();

            std::cout << "Enter PID of application to memory scan, or [c]ancel > ";
            std::cin >> pid;
			if (pid == 'c' || pid == 'C') { continue; }
            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
            if (!hProcess) {
                std::cerr << "Failed to open process. Error: " << GetLastError() << std::endl;
                return 1;
            }
			procName = GetProcessName(hProcess);
            matches.clear();
		}
        else if (selection == 'w') {
            if (matches.empty()) {
                std::cout << "No matches to write to. Perform a scan first." << std::endl;
                continue;
			}
            PrintMatches(hProcess, matches);
            
            int choice;
            std::cout << "Enter number of address to modify > ";
            std::cin >> choice;
            int newVal;
            std::cout << "Enter new value > ";
            std::cin >> newVal;
            
            WriteToAddress(hProcess, (LPVOID)matches[choice].address, newVal);
            PrintMatches(hProcess, matches);
        }
        else if (selection == 'r')
        {
            if (matches.empty()) {
                std::cout << "No previous matches to rescan. Perform an initial scan first." << std::endl;
                continue;
            }
            int newValue;
            std::cout << "Enter new value: ";
            std::cin >> newValue;

            matches = Rescan(hProcess, matches, newValue);
            std::cout << "Rescan narrowed down to " << matches.size() << " matches." << std::endl;
        }
        else if (selection == 'n')
        {
            if (!hProcess) {
                std::cout << "No process attached. Find a process first." << std::endl;
                continue;
			}
            std::cout << "Enter initial value to search (int) > ";
            std::cin >> searchValue;

            matches = InitialScanOptimized(hProcess, searchValue);
            std::cout << "Initial scan found " << matches.size() << " matches." << std::endl;
        }
        else if (selection == 'm')
        {
            if (!hProcess) {
                std::cout << "No process attached. Find a process first." << std::endl;
                continue;
            }

            uintptr_t manualAddress = 0;
            int manualValue = 0;

            while (true) {
                // Read value at manualAddress if set
                if (manualAddress != 0) {
                    SIZE_T bytesRead;
                    int tempValue = 0;
                    if (ReadProcessMemory(hProcess, (LPCVOID)manualAddress, &tempValue, sizeof(tempValue), &bytesRead)) {
                        manualValue = tempValue;
                    } else {
                        manualValue = 0;
                    }
                }

                std::cout << "--------------------------------------\n";
                std::cout << "Current address: 0x" << std::hex << manualAddress << std::dec << "\n"
                          << " Current value: " << manualValue << "\n";
                std::cout << "input [a]ddress; input [v]alue; [b]ack > ";
                char msel;
                std::cin >> msel;

                if (msel == 'a') {
                    std::cout << "Enter address (hex, e.g. 12345678): 0x";
                    std::string addrStr;
                    std::cin >> addrStr;
                    try {
                        manualAddress = std::stoull(addrStr, nullptr, 16);
                    } catch (...) {
                        std::cout << "Invalid address format.\n";
                        manualAddress = 0;
                    }
                } else if (msel == 'v') {
                    if (manualAddress == 0) {
                        std::cout << "Set an address first.\n";
                        continue;
                    }
                    std::cout << "Enter new value (int): ";
                    int newVal;
                    std::cin >> newVal;
                    SIZE_T bytesWritten;
                    if (WriteProcessMemory(hProcess, (LPVOID)manualAddress, &newVal, sizeof(newVal), &bytesWritten)) {
                        std::cout << "Value updated successfully!\n";
                    } else {
                        std::cerr << "Failed to write memory. Error: " << GetLastError() << std::endl;
                    }
                } else if (msel == 'b') {
                    break;
                }
            }
        }
        else if (selection == 'q') { break; }
    }
    
    if (hProcess)
    {
        CloseHandle(hProcess);
    }
    return 0;
}
