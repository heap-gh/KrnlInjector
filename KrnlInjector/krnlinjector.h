
#pragma once

#include <ntifs.h>
#include <wdm.h>
#include <ntddk.h>


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);
NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject);
NTSTATUS InjectorDispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS InjectorOpenCloseFileControl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);
NTSTATUS CreateDeviceAndLink(PDRIVER_OBJECT pDriverObject);