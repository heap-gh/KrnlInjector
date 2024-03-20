
#pragma once

#include <ntifs.h>
#include <wdm.h>
#include <ntddk.h>
#include <windef.h>
#include <basetsd.h>


#include "structs.h"


NTSTATUS ManualMap(PVOID inputBuffer, ULONG inputBufferLength, PVOID outputBuffer, ULONG outputBufferLength);
NTSTATUS GetBufferArguments(PVOID inputBuffer, ULONG inputBufferLength, PULONG pid, PANSI_STRING modulePath, PDWORD64 pConfigFlags);
PVOID AllocateDLLBytes(PANSI_STRING modulePath, PLONGLONG moduleSize);
NTSTATUS FreeManualMap(PVOID moduleBytes);
NTSTATUS FindTargetProcessHandle(PULONG pid, PANSI_STRING injectorBasePath);

