#include "Driver.h"
#include "Tokens.h"

UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\TokenDriver");
UNICODE_STRING SymLinkName = RTL_CONSTANT_STRING(L"\\??\\TokenLink");

PDEVICE_OBJECT DeviceObject = NULL;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS NtStatus;

	DriverObject->DriverUnload = Unload;

	NtStatus = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
	if (!NT_SUCCESS(NtStatus))
	{
		KdPrint(("IoCreateDevice Failed: %ws\r\n", NtStatus));
		return NtStatus;
	}

	NtStatus = IoCreateSymbolicLink(&SymLinkName, &DeviceName);
	if (!NT_SUCCESS(NtStatus))
	{
		KdPrint(("IoCreateSymbolicLink Failed: %ws\r\n", NtStatus));
		IoDeleteDevice(DeviceObject);
		return NtStatus;
	}

	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DriverObject->MajorFunction[i] = IRPDispatch;
	}

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IRPDispatchDevCTL;
	KdPrint(("TokenDriver Loaded \r\n"));

	return NtStatus;
}

NTSTATUS IRPDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION IrpStackPointer = IoGetCurrentIrpStackLocation(Irp);

	NTSTATUS NtStatus;

	switch (IrpStackPointer->MajorFunction)
	{
	case IRP_MJ_CREATE:
		KdPrint(("TokenDriver Create Request Recieved\r\n"));
		NtStatus = STATUS_SUCCESS;
		break;
	case IRP_MJ_CLOSE:
		KdPrint(("TokenDriver Close Request Recieved\r\n"));
		NtStatus = STATUS_SUCCESS;
		break;
	default:
		NtStatus = STATUS_INVALID_PARAMETER;
		break;
	}

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = NtStatus;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return NtStatus;
}

NTSTATUS IRPDispatchDevCTL(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION IrpStackPointer = IoGetCurrentIrpStackLocation(Irp);

	NTSTATUS NtStatus = STATUS_SUCCESS;
	size_t messageLength = 0;

	PVOID Buffer = Irp->AssociatedIrp.SystemBuffer;
	ULONG InLength = IrpStackPointer->Parameters.DeviceIoControl.InputBufferLength;
	ULONG OutLength = IrpStackPointer->Parameters.DeviceIoControl.OutputBufferLength;
	//WCHAR* Message = L"Output from driver operation";
	//KdPrint(("IOCTL is %u \r\n", IrpStackPointer->Parameters.DeviceIoControl.IoControlCode));
	switch (IrpStackPointer->Parameters.DeviceIoControl.IoControlCode)
	{
	/*
	case DEVICE_SEND:
		KdPrint(("Send Data is %ws \r\n", Buffer));
		messageLength = (wcsnlen(Buffer,511) + 1) * 2;
		break;
	case DEVICE_RECIEVE:
		KdPrint(("Recieve Message is %ws \r\n", Message));
		wcsncpy_s(Buffer, ((OutLength - 1) / 2), Message, wcsnlen_s(Message, ((OutLength - 1) / 2)));
		messageLength = (wcsnlen(Buffer, 511) + 1) * 2;
		break;
	*/
	case DEVICE_FREEZE:
		ULONGLONG output_freeze[5];
		UnFreezeToken(&output_freeze);

		memcpy_s(Buffer, OutLength, output_freeze, sizeof(output_freeze));
		messageLength = sizeof(output_freeze);
		break;
	case DEVICE_FREEZE_ID:
		if (InLength != sizeof(ULONG))
		{
			KdPrint(("Incorrect InLength is: %u \r\n", InLength));
			break;
		}
		SHORT* ptrPid = Buffer;
		ULONG pid = ptrPid[0] + (ptrPid[1] << 8) + (ptrPid[2] << 16) + (ptrPid[3] << 24);

		ULONGLONG output_freeze_pid[5];
		UnFreezeTokenByPid(pid, &output_freeze_pid);

		memcpy_s(Buffer, OutLength, output_freeze_pid, sizeof(output_freeze_pid));
		messageLength = sizeof(output_freeze_pid);
		break;
	case DEVICE_PRIVILEGE_ADD:
		if (InLength != sizeof(ULONGLONG))
		{
			KdPrint(("Incorrect InLength is: %u (%u Expected)\r\n", InLength, sizeof(ULONG)));
			break;
		}
		SHORT* ptrPriv = Buffer;
		ULONGLONG uPriv = ptrPriv[0] + (ptrPriv[1] << 8) + (ptrPriv[2] << 16) + (ptrPriv[3] << 24);
		
		ULONGLONG output_privilege[9];
		AddTokenPrivilege((PRIVILEGES)uPriv, &output_privilege);
		KdPrint(("0x%llp\r\n", output_privilege[0]));

		memcpy_s(Buffer, OutLength, output_privilege, sizeof(output_privilege));
		messageLength = sizeof(output_privilege);
		break;
	case DEVICE_PRIVILEGE_ADD_ID:
		if (InLength != (sizeof(ULONG) + sizeof(ULONGLONG)))
		{
			KdPrint(("Incorrect InLength is: %u (%u Expected)\r\n", InLength, sizeof(PRIVILEGE_DATA)));
			break;
		}
		ULONGLONG output_privilege_pid[9];
		PPRIVILEGE_DATA data = (PPRIVILEGE_DATA)Buffer;
		AddTokenPrivilegeByPid(data->ProcessID, data->Privilege, &output_privilege_pid);

		memcpy_s(Buffer, OutLength, output_privilege_pid, sizeof(output_privilege_pid));
		messageLength = sizeof(output_privilege_pid);
		break;
	default:
		NtStatus = STATUS_INVALID_PARAMETER;
		KdPrint(("%u \r\n",DEVICE_FREEZE));
		KdPrint(("Control Code %u is Invalid \r\n", IrpStackPointer->Parameters.DeviceIoControl.IoControlCode));
		break;
	}

	KdPrint(("Message Length is %u \r\n", messageLength));
	Irp->IoStatus.Information = messageLength;
	Irp->IoStatus.Status = NtStatus;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return NtStatus;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	IoDeleteSymbolicLink(&SymLinkName);
	IoDeleteDevice(DeviceObject);
	KdPrint(("TokenDriver Unloaded \r\n\r\n"));
}