
#include "krnlinjector.h"
#include "ManualMap.h"

#define IOCTL_ManualMap CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)



NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{

	UNREFERENCED_PARAMETER(pRegistryPath);

	pDriverObject->DriverUnload = UnloadDriver;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = InjectorDispatchDeviceControl;
    pDriverObject->MajorFunction[IRP_MJ_CREATE] = InjectorOpenCloseFileControl;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = InjectorOpenCloseFileControl;


    NTSTATUS bCreateDeviceAndLink = CreateDeviceAndLink(pDriverObject);

    if (NT_SUCCESS(bCreateDeviceAndLink))
    {

        DbgPrint("[+] Created Device and Link\n");
    }
    else
    {
        DbgPrint("[-] Failed to create Device and Link\n");
        return STATUS_UNSUCCESSFUL;
    }


    DbgPrint("[+] Success\n");

	return STATUS_SUCCESS;

}


NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject)
{

	UNREFERENCED_PARAMETER(pDriverObject);


	return STATUS_SUCCESS;

}


NTSTATUS CreateDeviceAndLink(PDRIVER_OBJECT pDriverObject)
{


    UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\krnlinjector");
    UNICODE_STRING device_symbolic_name = RTL_CONSTANT_STRING(L"\\??\\krnlinjectorlink");

    NTSTATUS status_create_device = IoCreateDevice(pDriverObject,
        0,
        &device_name,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &pDriverObject->DeviceObject);


    if (NT_SUCCESS(status_create_device))
    {
        DbgPrint("[+] Initializing Device success\n");
    }
    else
    {
        DbgPrint("[-] Initializing Device failed\n");
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS status_create_link = IoCreateSymbolicLink(&device_symbolic_name , &device_name);

    if (NT_SUCCESS(status_create_link))
    {
        DbgPrint("[+] Initializing Link success \n");
    }
    else 
    {
        DbgPrint("[-] Initializing Link failed \n");
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;

}



NTSTATUS InjectorOpenCloseFileControl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{

    UNREFERENCED_PARAMETER(pDeviceObject);

    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(pIrp);

    ULONG ioctl = irpStack->Parameters.DeviceIoControl.IoControlCode;

    switch (ioctl)
    {

    case IRP_MJ_CREATE:
    {
        DbgPrint("[+] Openend File Handle\n");
        break;
    }

    case IRP_MJ_CLOSE:
    {
        DbgPrint("[+] Closed File Handle\n");
        break;
    }

    default:
        break;

    }


    pIrp->IoStatus.Information = 0;
    pIrp->IoStatus.Status = status;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return status;

}


NTSTATUS InjectorDispatchDeviceControl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{


    UNREFERENCED_PARAMETER(pDeviceObject);

    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(pIrp);

    ULONG ioctl = irpStack->Parameters.DeviceIoControl.IoControlCode;
    PVOID inputBuffer = pIrp->AssociatedIrp.SystemBuffer;
    ULONG inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    PVOID outputBuffer = pIrp->AssociatedIrp.SystemBuffer;
    ULONG outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;


    switch (ioctl)
    {

    case IOCTL_ManualMap:
    {
        DbgPrint("[+] ManualMap\n");
        ManualMap(inputBuffer, inputBufferLength, outputBuffer, outputBufferLength);
        break;
    }
       

    default:
    {  
        status = STATUS_INVALID_DEVICE_REQUEST;
        DbgPrint("[+] Default\n");
        break;
    }

    }

 
    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = 0; 
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return status;


}