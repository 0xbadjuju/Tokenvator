#include "Tokens.h"

	//https://docs.microsoft.com/en-us/windows-hardware/drivers/dashboard/register-for-the-hardware-program
	//https://www.digicert.com/friends/sysdev/

	//https://wasm.in/threads/zwsetinformationprocess-processaccesstoken.29483/
	//https://j00ru.vexillium.org/2012/10/introducing-the-usb-stick-of-death/
	//https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/blob/1cdb724a0712902fe50196ae95e727bfe5c0081b/Exploit/Common.h
	//https://ntopcode.wordpress.com/2018/02/26/anatomy-of-the-process-environment-block-peb-windows-internals/
	//https://www.nirsoft.net/kernel_struct/vista/EPROCESS.html

	/*
	ExAcquirePushLockExclusive(&p->ProcessLock);
	ExReleasePushLockExclusive(&p->ProcessLock);
	*/

VOID UnFreezeToken(ULONGLONG output[5])
{
	PEPROCESS ptrEProcess = PsGetCurrentProcess();
	KdPrint(("PEPROCESS Base Address  : 0x%llp\r\n", ptrEProcess));
	output[0] = (uintptr_t)ptrEProcess;

	ULONG Flags2 = *((int*)((char*)ptrEProcess + 0x460));
	KdPrint(("PEPROCESS Flags2 Offset : 0x%llp\r\n", (char*)ptrEProcess + 0x460));
	output[1] = (uintptr_t)((char*)ptrEProcess + 0x460);

	KdPrint(("Flags2 Original Value   : 0x%x\r\n", Flags2));
	output[2] = (uintptr_t)Flags2;
	KdPrint(("Flags2 Updated Value    : 0x%x\r\n", Flags2 ^ 0x00008000));
	output[3] = (uintptr_t)Flags2 ^ 0x00008000;
	KdPrint(("Flags2 band : %x\r\n", Flags2 & 0x00008000));
	output[4] = (uintptr_t)Flags2 & 0x00008000;

	Flags2 ^= 0x00008000;
	*((int*)((char*)ptrEProcess + 0x300)) = Flags2;
}

VOID UnFreezeTokenByPid(ULONG ProcessId, ULONGLONG output[5])
{
	PEPROCESS ptrEProcess = NULL;
	NTSTATUS NtStatus = PsLookupProcessByProcessId((HANDLE)ProcessId, &ptrEProcess);
	if (STATUS_SUCCESS != NtStatus)
	{
		KdPrint(("Error : %u\r\n", RtlNtStatusToDosError(NtStatus)));
		return;
	}
	KdPrint(("PEPROCESS Base Address  : 0x%llp\r\n", ptrEProcess));
	output[0] = (uintptr_t)ptrEProcess;

	ULONG Flags2 = *((int*)((char*)ptrEProcess + 0x460));
	KdPrint(("PEPROCESS Flags2 Offset : 0x%llp\r\n", (char*)ptrEProcess + 0x460));
	output[1] = (uintptr_t)((char*)ptrEProcess + 0x460);

	KdPrint(("Flags2 Original Value   : 0x%x\r\n", Flags2));
	output[2] = (uintptr_t)Flags2;
	KdPrint(("Flags2 Updated Value    : 0x%x\r\n", Flags2 ^ 0x00008000));
	output[3] = (uintptr_t)Flags2 ^ 0x00008000;
	KdPrint(("Flags2 band : %x\r\n", Flags2 & 0x00008000));
	output[4] = (uintptr_t)Flags2 & 0x00008000;

	Flags2 ^= 0x00008000;
	*((int*)((char*)ptrEProcess + 0x300)) = Flags2;
}

VOID _UnfreezeToken(PEPROCESS ptrEProcess, ULONGLONG output[5])
{
	KdPrint(("PEPROCESS Base Address  : 0x%llp\r\n", ptrEProcess));
	output[0] = (uintptr_t)ptrEProcess;

	ULONG Flags2 = *((int*)((char*)ptrEProcess + 0x460));
	KdPrint(("PEPROCESS Flags2 Offset : 0x%llp\r\n", (char*)ptrEProcess + 0x460));
	output[1] = (uintptr_t)((char*)ptrEProcess + 0x460);

	KdPrint(("Flags2 Original Value   : 0x%x\r\n", Flags2));
	output[2] = (uintptr_t)Flags2;
	KdPrint(("Flags2 Updated Value    : 0x%x\r\n", Flags2 ^ 0x00008000));
	output[3] = (uintptr_t)Flags2 ^ 0x00008000;
	KdPrint(("Flags2 band : %x\r\n", Flags2 & 0x00008000));
	output[4] = (uintptr_t)Flags2 & 0x00008000;

	Flags2 ^= 0x00008000;
	*((int*)((char*)ptrEProcess + 0x300)) = Flags2;
}

VOID OpenToken(PEPROCESS ptrEProcess)
{
	PACCESS_TOKEN ptrAccessToken = PsReferencePrimaryToken(ptrEProcess);
	KdPrint(("AccessToken: 0x%llp\r\n", ptrAccessToken));
}

VOID AddTokenPrivilege(PRIVILEGES privilege, ULONGLONG output[9])
{
	PEPROCESS ptrEProcess = PsGetCurrentProcess();
	output[0] = (uintptr_t)ptrEProcess;
	KdPrint(("PEPROCESS Base Address             : 0x%llp\r\n", ptrEProcess));
	KdPrint(("PEPROCESS Base Address             : 0x%llp\r\n", output[0]));

	//When originally attempted 0x358
	//Current version 0x4b8
	PVOID* ptrFastRef = ((char*)ptrEProcess + 0x4b8);
	KdPrint(("EX_FAST_REF Base Address           : 0x%llp\r\n", ptrFastRef));
	output[1] = (uintptr_t)ptrFastRef;

	KdPrint(("EX_FAST_REF Data                   : 0x%llp\r\n", *ptrFastRef));
	output[2] = (uintptr_t)*ptrFastRef;

	PVOID tokenAddress = ((uintptr_t)*ptrFastRef & (uintptr_t)0xfffffffffffffff0);
	KdPrint(("TOKEN Base Address                 : 0x%llp\r\n", tokenAddress));
	output[3] = (uintptr_t)tokenAddress;

	tokenAddress = ((char*)tokenAddress + 0x40);
	KdPrint(("PSEP_TOKEN_PRIVILEGES Base Address : 0x%llp\r\n", tokenAddress));
	output[4] = (uintptr_t)tokenAddress;

	PSEP_TOKEN_PRIVILEGES privs = tokenAddress;
	KdPrint(("Current Present Value              : 0x%llp\r\n", privs->Present));
	output[5] = (uintptr_t)privs->Present;

	privs->Present |= privilege;
	KdPrint(("Updated Present Value              : 0x%llp\r\n", privs->Present));
	output[6] = (uintptr_t)privs->Present;

	KdPrint(("Enabled                            : 0x%llp\r\n", privs->Enabled));
	output[7] = (uintptr_t)privs->Enabled;

	KdPrint(("EnabledByDefault                   : 0x%llp\r\n", privs->EnabledByDefault));
	output[8] = (uintptr_t)privs->EnabledByDefault;
}

VOID AddTokenPrivilegeByPid(ULONG ProcessId, PRIVILEGES privilege, ULONGLONG output[9])
{
	PEPROCESS ptrEProcess = NULL;
	NTSTATUS NtStatus = PsLookupProcessByProcessId((HANDLE)ProcessId, &ptrEProcess);
	if (STATUS_SUCCESS != NtStatus)
	{
		KdPrint(("Error : %u\r\n", RtlNtStatusToDosError(NtStatus)));
		return;
	}
	
	output[0] = (uintptr_t)ptrEProcess;
	KdPrint(("PEPROCESS Base Address             : 0x%llp\r\n", ptrEProcess));
	KdPrint(("PEPROCESS Base Address             : 0x%llp\r\n", output[0]));

	PVOID* ptrFastRef = ((char*)ptrEProcess + 0x4b8);
	KdPrint(("EX_FAST_REF Base Address           : 0x%llp\r\n", ptrFastRef));
	output[1] = (uintptr_t)ptrFastRef;

	KdPrint(("EX_FAST_REF Data                   : 0x%llp\r\n", *ptrFastRef));
	output[2] = (uintptr_t)*ptrFastRef;

	PVOID tokenAddress = ((uintptr_t)*ptrFastRef & (uintptr_t)0xfffffffffffffff0);
	KdPrint(("TOKEN Base Address                 : 0x%llp\r\n", tokenAddress));
	output[3] = (uintptr_t)tokenAddress;

	tokenAddress = ((char*)tokenAddress + 0x40);
	KdPrint(("PSEP_TOKEN_PRIVILEGES Base Address : 0x%llp\r\n", tokenAddress));
	output[4] = (uintptr_t)tokenAddress;

	PSEP_TOKEN_PRIVILEGES privs = tokenAddress;
	KdPrint(("Current Present Value              : 0x%llp\r\n", privs->Present));
	output[5] = (uintptr_t)privs->Present;

	privs->Present |= privilege;
	KdPrint(("Updated Present Value              : 0x%llp\r\n", privs->Present));
	output[6] = (uintptr_t)privs->Present;

	KdPrint(("Enabled                            : 0x%llp\r\n", privs->Enabled));
	output[7] = (uintptr_t)privs->Enabled;

	KdPrint(("EnabledByDefault                   : 0x%llp\r\n", privs->EnabledByDefault));
	output[8] = (uintptr_t)privs->EnabledByDefault;
}

VOID _AddTokenPrivilege(PEPROCESS ptrEProcess, PRIVILEGES privilege, ULONGLONG output[9])
{
	output[0] = (uintptr_t)ptrEProcess;
	KdPrint(("PEPROCESS Base Address             : 0x%llp\r\n", ptrEProcess));
	KdPrint(("PEPROCESS Base Address             : 0x%llp\r\n", output[0]));

	PVOID* ptrFastRef = ((char*)ptrEProcess + 0x4b8);
	KdPrint(("EX_FAST_REF Base Address           : 0x%llp\r\n", ptrFastRef));
	output[1] = (uintptr_t)ptrFastRef;

	KdPrint(("EX_FAST_REF Data                   : 0x%llp\r\n", *ptrFastRef));
	output[2] = (uintptr_t)*ptrFastRef;

	PVOID tokenAddress = ((uintptr_t)*ptrFastRef & (uintptr_t)0xfffffffffffffff0);
	KdPrint(("TOKEN Base Address                 : 0x%llp\r\n", tokenAddress));
	output[3] = (uintptr_t)tokenAddress;

	tokenAddress = ((char*)tokenAddress + 0x40);
	KdPrint(("PSEP_TOKEN_PRIVILEGES Base Address : 0x%llp\r\n", tokenAddress));
	output[4] = (uintptr_t)tokenAddress;

	PSEP_TOKEN_PRIVILEGES privs = tokenAddress;
	KdPrint(("Current Present Value              : 0x%llp\r\n", privs->Present));
	output[5] = (uintptr_t)privs->Present;

	privs->Present |= privilege;
	KdPrint(("Updated Present Value              : 0x%llp\r\n", privs->Present));
	output[6] = (uintptr_t)privs->Present;

	KdPrint(("Enabled                            : 0x%llp\r\n", privs->Enabled));
	output[7] = (uintptr_t)privs->Enabled;

	KdPrint(("EnabledByDefault                   : 0x%llp\r\n", privs->EnabledByDefault));
	output[8] = (uintptr_t)privs->EnabledByDefault;
}