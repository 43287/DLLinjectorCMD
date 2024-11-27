#pragma once
#include"header.h"

class ModuleFuncLoader {
private:
	HMODULE hModule;
	PVOID pFunc;
public:
	ModuleFuncLoader(LPCSTR moduleName, LPCSTR funcName) {
		hModule = GetModuleHandleA(moduleName);
		if (!hModule)
			throw std::runtime_error(std::string("模块打开失败:") + moduleName);
		pFunc = GetProcAddress(hModule, funcName);
		if (!pFunc)
			throw std::runtime_error(std::string("函数查找失败:") + funcName);
	}
	HMODULE module() {
		return hModule;
	}
	PVOID func() {
		return pFunc;
	}
};




class Injector
{
private:
	LPCTSTR DLLpath;
	std::wstring mode;
public:
	//初始化
	Injector(LPCTSTR path) {
		DLLpath = path;
		mode = L"remoteThread";
	}
	Injector(LPCTSTR path, std::wstring m) {
		DLLpath = path;
		mode = m;
	}

	//权限提升
	BOOL setPrivilege(LPCTSTR targetPrivilege, BOOL adjust = TRUE);
	BOOL setPrivilege() {
		return setPrivilege(SE_DEBUG_NAME);
	}

	//注入相关


private:
	std::vector<DWORD> GetProcessIdsByName(const LPCWSTR& processName) {
		std::vector<DWORD> processIds;
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE) {
			throw std::runtime_error("创建快照失败");
		}

		PROCESSENTRY32 pe;
		pe.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(hSnapshot, &pe)) {
			do {
				if (processName == pe.szExeFile) {
					processIds.push_back(pe.th32ProcessID);
				}
			} while (Process32Next(hSnapshot, &pe));
		}
		CloseHandle(hSnapshot);

		if (processIds.empty()) {
			throw std::runtime_error("未找到目标进程");
		}

		return processIds;
	}


	//查找目标进程句柄

public:
	HANDLE findtargetHandle(DWORD dwPid) {
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
		if (!hProcess)
			throw std::runtime_error(std::string("目标进程打开失败,PID:") + std::to_string(dwPid));
		return hProcess;
	}
	HANDLE findtargetHandle(LPCWSTR processName) {
		LPCWSTR wpName = processName;
		std::vector<DWORD> nameVec = GetProcessIdsByName(wpName);
		if (nameVec.size() == 1) {
			return findtargetHandle(nameVec[0]);
		}
		std::cout << "有多个目标进程,请选择你需要注入的进程" << std::endl;
		for (auto pid : nameVec) {
			std::cout << pid << ',';
		}
		std::cout << std::endl;
		DWORD pid;
		std::cin >> pid;
		return findtargetHandle(pid);
	}
	//inject主逻辑
private:
	void toLowerCase(std::string& str) {
		std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) {
			return std::tolower(c);
			});
	}

	//检查目标进程是否有对应模块
	HANDLE isLoaded(DWORD pid);

public:
	void inject();
	void eject();
};

