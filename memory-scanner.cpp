#include <iostream>
#include <windows.h>

int main()
{
    DWORD pid;
    std::cout << "Enter PID of application to memory scan: ";
    std::cin >> pid;

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Failed to open process. Error: " << GetLastError() << std::endl;
        return 1;
    }
}
