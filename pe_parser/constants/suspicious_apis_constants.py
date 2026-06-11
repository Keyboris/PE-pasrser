SUSPICIOUS_APIS = {

    "networking": [
        # Winsock / raw sockets
        "WSAStartup", "WSACleanup", "WSASocketA", "WSASocketW",
        "socket", "connect", "bind", "listen", "accept",
        "send", "recv", "sendto", "recvfrom",
        "gethostbyname", "getaddrinfo",
        # WinINet — high-level HTTP
        "InternetOpenA", "InternetOpenW",
        "InternetConnectA", "InternetConnectW",
        "HttpOpenRequestA", "HttpOpenRequestW",
        "HttpSendRequestA", "HttpSendRequestW",
        "InternetReadFile", "InternetWriteFile",
        "InternetOpenUrlA", "InternetOpenUrlW",
        # WinHTTP — used by many RATs as an alternative to WinINet
        "WinHttpOpen", "WinHttpConnect",
        "WinHttpOpenRequest", "WinHttpSendRequest",
        "WinHttpReceiveResponse", "WinHttpReadData",
        # DNS
        "DnsQuery_A", "DnsQuery_W",
    ],

    "registry": [
        # Opening / creating keys
        "RegOpenKeyA", "RegOpenKeyW",
        "RegOpenKeyExA", "RegOpenKeyExW",
        "RegCreateKeyA", "RegCreateKeyW",
        "RegCreateKeyExA", "RegCreateKeyExW",
        # Reading values
        "RegQueryValueA", "RegQueryValueW",
        "RegQueryValueExA", "RegQueryValueExW",
        "RegEnumKeyA", "RegEnumKeyW",
        "RegEnumKeyExA", "RegEnumKeyExW",
        "RegEnumValueA", "RegEnumValueW",
        # Writing / deleting — higher severity
        "RegSetValueA", "RegSetValueW",
        "RegSetValueExA", "RegSetValueExW",
        "RegDeleteKeyA", "RegDeleteKeyW",
        "RegDeleteValueA", "RegDeleteValueW",
        "RegCloseKey",
    ],

    "cryptography": [
        # CryptoAPI (legacy)
        "CryptAcquireContextA", "CryptAcquireContextW",
        "CryptGenKey", "CryptDeriveKey", "CryptDestroyKey",
        "CryptEncrypt", "CryptDecrypt",
        "CryptHashData", "CryptCreateHash", "CryptGetHashParam",
        "CryptGenRandom",
        "CryptImportKey", "CryptExportKey",
        # BCrypt (modern CNG) — used by ransomware
        "BCryptOpenAlgorithmProvider", "BCryptCloseAlgorithmProvider",
        "BCryptGenerateSymmetricKey", "BCryptDestroyKey",
        "BCryptEncrypt", "BCryptDecrypt",
        "BCryptGenRandom",
        "BCryptImportKeyPair", "BCryptExportKey",
    ],

    "process_injection": [
        # Classic remote injection
        "VirtualAllocEx", "VirtualAlloc", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory",
        "CreateRemoteThread", "CreateRemoteThreadEx",
        "SetThreadContext", "GetThreadContext",
        # Process hollowing / manipulation
        "OpenProcess", "TerminateProcess",
        "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
        "NtWriteVirtualMemory", "ZwWriteVirtualMemory",
        # APC injection
        "QueueUserAPC",
        # Shellcode / reflective loading
        "LoadLibraryA", "LoadLibraryW",
        "LoadLibraryExA", "LoadLibraryExW",
        "GetProcAddress",
    ],

    "anti_debugging": [
        # Direct debugger checks
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",   # ProcessDebugPort check
        "OutputDebugStringA", "OutputDebugStringW",
        # Timing-based detection
        "GetTickCount", "GetTickCount64",
        "QueryPerformanceCounter",
        # Hardware breakpoint / context inspection
        "GetThreadContext",
        # Heap flag inspection
        "GetProcessHeap", "HeapAlloc",
        # Exception-based anti-debug
        "RaiseException", "UnhandledExceptionFilter",
        "SetUnhandledExceptionFilter",
    ],

    "anti_analysis": [
        # VM / sandbox detection
        "GetSystemInfo", "GlobalMemoryStatusEx",
        "EnumDisplayDevices",
        "CreateToolhelp32Snapshot",       # process enumeration
        "Process32First", "Process32Next", # scanning for analysis tools
        "GetModuleHandleA", "GetModuleHandleW",
        # Sleep-based sandbox evasion
        "Sleep", "WaitForSingleObject", "WaitForMultipleObjects",
        "NtDelayExecution",
        # Self-deletion / cleanup
        "DeleteFileA", "DeleteFileW",
        "MoveFileExA", "MoveFileExW",     # MOVEFILE_DELAY_UNTIL_REBOOT
    ],

    "keylogging": [
        "SetWindowsHookExA", "SetWindowsHookExW",
        "UnhookWindowsHookEx",
        "GetAsyncKeyState", "GetKeyState", "GetKeyboardState",
        "MapVirtualKeyA", "MapVirtualKeyW",
        # Clipboard theft (often paired with keyloggers)
        "OpenClipboard", "GetClipboardData", "SetClipboardData",
    ],

    "persistence": [
        # Scheduled tasks
        "CoCreateInstance",              # Task Scheduler COM interface
        # Services
        "CreateServiceA", "CreateServiceW",
        "OpenServiceA", "OpenServiceW",
        "StartServiceA", "StartServiceW",
        "ChangeServiceConfigA", "ChangeServiceConfigW",
        # Startup via registry — caught by registry category too,
        # but listing here signals persistence-specific intent
        "RegSetValueExA", "RegSetValueExW",
        # DLL hijacking / side-loading
        "SetDllDirectoryA", "SetDllDirectoryW",
        "AddDllDirectory",
    ],

    "file_system": [
        # Enumeration — ransomware uses these to find files to encrypt
        "FindFirstFileA", "FindFirstFileW",
        "FindNextFileA", "FindNextFileW",
        "FindFirstFileExA", "FindFirstFileExW",
        # Creation / writing
        "CreateFileA", "CreateFileW",
        "WriteFile", "ReadFile",
        "CopyFileA", "CopyFileW",
        "MoveFileA", "MoveFileW",
        # Volume / shadow copy — ransomware specific
        "GetLogicalDrives", "GetDriveTypeA", "GetDriveTypeW",
        "DeviceIoControl",               # used to delete VSS snapshots
    ],

    "privilege_escalation": [
        "AdjustTokenPrivileges",
        "LookupPrivilegeValueA", "LookupPrivilegeValueW",
        "OpenProcessToken", "OpenThreadToken",
        "DuplicateToken", "DuplicateTokenEx",
        "ImpersonateLoggedOnUser",
        "SetTokenInformation",
    ],

}