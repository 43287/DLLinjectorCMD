#include "Injector.h"

BOOL Injector::setPrivilege(LPCTSTR targetPrivilege, BOOL adjust)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		std::cerr << "无法打开进程令牌。错误: " << GetLastError() << std::endl;
		return FALSE;
	}
	if (!LookupPrivilegeValue(NULL, targetPrivilege, &luid)) {
		std::cerr << "目标权限未找到。错误: " << GetLastError() << std::endl;
		CloseHandle(hToken);
		return FALSE;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (adjust)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		std::cerr << "调整权限失败。错误: " << GetLastError() << std::endl;
		CloseHandle(hToken);
		return FALSE;
	}

	return TRUE;
}

HANDLE Injector::isLoaded(DWORD pid)
{
	HANDLE hModule = nullptr;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (hSnapshot == INVALID_HANDLE_VALUE || hSnapshot == NULL)
		throw std::runtime_error("创建快照失败");
	MODULEENTRY32 me;
	me.dwSize = sizeof(MODULEENTRY32);
	if (Module32First(hSnapshot, &me)) {
		do
		{
			if (!_wcsicmp(PathFindFileNameW(DLLpath), me.szModule) &&
				!_wcsicmp(DLLpath, me.szExePath)) {
				hModule = me.hModule;
				break;
			}
		} while (Module32Next(hSnapshot, &me));
	}
	CloseHandle(hSnapshot);
	return hModule;
}

void Injector::inject()
{
	auto ploadLibrary = (LPTHREAD_START_ROUTINE)ModuleFuncLoader("kernel32", "LoadLibraryW").func();
	std::string findMode;
	std::cin >> findMode;
	toLowerCase(findMode);
	HANDLE hProcess = NULL;
	if (findMode == "pid") {
		DWORD pid;
		std::cin >> pid;
		hProcess = findtargetHandle(pid);
	}
	if (findMode == "name") {
		std::wstring name;
		std::wcin >> name;
		LPCWSTR lname = name.c_str();
		hProcess = findtargetHandle(lname);
	}
	if (!hProcess)
		throw std::runtime_error("模式匹配失败");
	DWORD pathLen = (_tcslen(DLLpath) + 1) * sizeof(TCHAR);

	LPVOID lpDllpath = VirtualAllocEx(hProcess, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!lpDllpath)
		throw std::runtime_error("目标进程内存分配失败");
	SIZE_T bytesWritten;
	if (!WriteProcessMemory(hProcess, lpDllpath, DLLpath, pathLen, &bytesWritten))
		throw std::runtime_error("写入DLL路径失败");
	HANDLE hThread = NULL;
	if (hThread = CreateRemoteThread(hProcess, NULL, NULL, ploadLibrary, lpDllpath, NULL, NULL), !hThread)
		throw std::runtime_error("远程线程创建失败");
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	CloseHandle(hProcess);

}

void Injector::eject()
{
	auto pfreelibrary = (LPTHREAD_START_ROUTINE)ModuleFuncLoader("kernel32", "FreeLibrary").func();
	std::string findMode;
	std::cin >> findMode;
	toLowerCase(findMode);
	HANDLE hProcess = NULL;
	if (findMode == "pid") {
		DWORD pid;
		std::cin >> pid;
		hProcess = findtargetHandle(pid);
	}
	if (findMode == "name") {
		std::wstring name;
		std::wcin >> name;
		LPCWSTR lname = name.c_str();
		hProcess = findtargetHandle(lname);
	}
	if (!hProcess)
		throw std::runtime_error("模式匹配失败");

	DWORD pid = GetProcessId(hProcess);
	HANDLE hModule = isLoaded(pid);
	if (hModule == INVALID_HANDLE_VALUE || hModule == NULL)
	{
		std::cout << "目标进程 " << pid << " 没有该模块" << std::endl;
		return;
	}

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfreelibrary, hModule, 0, NULL);
	if (!hThread) {
		throw std::runtime_error("远程线程创建失败");
	}
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	CloseHandle(hModule);
	CloseHandle(hProcess);
}
