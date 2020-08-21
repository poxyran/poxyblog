import idautils
import idc

from struct import unpack

api_list = ["CryptExportKey", "RegOpenKeyExW", "RegSetValueExW", "RegCreateKeyExW", "RegCloseKey", "GetTokenInformation", "OpenServiceW", "StartServiceW", "CryptCreateHash", "CryptHashData", "CryptDestroyHash", "CryptGetHashParam", "CryptDestroyKey", "CryptAcquireContextW", "CryptEncrypt", "CryptDecrypt", "GetUserNameW", "CryptImportKey", "CryptGenKey", "CryptReleaseContext", "CloseServiceHandle", "OpenSCManagerW", "DeleteService", "ControlService", "OpenProcessToken", "CryptStringToBinaryA", "IcmpSendEcho", "IcmpSendEcho2", "IcmpParseReplies", "GetAdaptersInfo", "IcmpCreateFile", "IcmpCloseHandle", "SetEvent", "WaitForSingleObjectEx", "GetLogicalDrives", "FindFirstFileW", "FindNextFileW", "WaitForMultipleObjects", "GetQueuedCompletionStatus", "JUNK_ENTRY", "ResumeThread", "PostQueuedCompletionStatus", "GetExitCodeThread", "TerminateThread", "CreateThread", "ExitProcess", "CreateIoCompletionPort", "HeapCreate", "RtlFreeHeap", "HeapLock", "RtlAllocateHeap", "HeapDestroy", "CreateEventW", "RtlSizeHeap", "RtlGetLastWin32Error", "CreateProcessW", "WaitForSingleObject", "GetCurrentProcess", "lstrcpyW", "Process32FirstW", "lstrcatW", "Process32NextW", "CreateToolhelp32Snapshot", "OpenProcess", "TerminateProcess", "GetShortPathNameW", "GetEnvironmentVariableW", "OpenMutexW", "CreateMutexW", "GetModuleFileNameW", "FlushFileBuffers", "WideCharToMultiByte", "RtlDeleteCriticalSection", "InitializeCriticalSection", "RtlLeaveCriticalSection", "RtlEnterCriticalSection", "GetComputerNameW", "CloseHandle", "DeleteFileW", "SetFileAttributesW", "GetProcessHeap", "SetEnvironmentVariableW", "FreeEnvironmentStringsW", "GetEnvironmentStringsW", "GetCommandLineW", "GetCommandLineA", "GetOEMCP", "GetACP", "IsValidCodePage", "FindFirstFileExW", "VirtualQuery", "RtlReAllocateHeap", "GetTimeZoneInformation", "ReadConsoleW", "SetStdHandle", "EnumSystemLocalesW", "GetUserDefaultLCID", "IsValidLocale", "GetTimeFormatW", "CreateFileW", "WriteFile", "GetFileSizeEx", "ReadFile", "WriteConsoleW", "SetEndOfFile", "HeapUnlock", "GetDateFormatW", "GetFullPathNameW", "RtlSetLastWin32Error", "InitializeCriticalSectionAndSpinCount", "SwitchToThread", "TlsAlloc", "TlsGetValue", "TlsSetValue", "TlsFree", "GetSystemTimeAsFileTime", "GetModuleHandleW", "GetProcAddress", "RtlEncodePointer", "RtlDecodePointer", "MultiByteToWideChar", "GetStringTypeW", "CompareStringW", "LCMapStringW", "GetLocaleInfoW", "GetCPInfo", "IsProcessorFeaturePresent", "IsDebuggerPresent", "UnhandledExceptionFilter", "SetUnhandledExceptionFilter", "GetStartupInfoW", "QueryPerformanceCounter", "GetCurrentProcessId", "GetCurrentThreadId", "RtlInitializeSListHead", "LocalFree", "RtlUnwind", "RaiseException", "FreeLibrary", "LoadLibraryExW", "GetDriveTypeW", "GetFileInformationByHandle", "GetFileType", "PeekNamedPipe", "SystemTimeToTzSpecificLocalTime", "FileTimeToSystemTime", "GetModuleHandleExW", "GetStdHandle", "SetFilePointerEx", "GetConsoleCP", "GetConsoleMode", "GetCurrentDirectoryW", "WNetGetConnectionW", "NetShareEnum", "NetApiBufferFree", "VariantClear", "SHGetFolderPathW", "ShellExecuteExW", "SHEmptyRecycleBinW", "ShellExecuteW", "inet_addr"]

start = idc.read_selection_start()
end = idc.read_selection_end()

index = 0

if start != BADADDR:
	print "[+] Fixing IAT. Start: %x - End: %x - Size: %x" % (start, end, end - start)
	print "--------------------------"
	while start < end:
		bytes = get_bytes(start, 4)
		if unpack("<L", bytes)[0] != 0:
			idc.set_name(start, api_list[index])
			print "--> Name: %s set at: %x" % (api_list[index], start)
			index +=1
		else:
			print "[!] Bytes are zero at: %x" % start
		start += 4
		