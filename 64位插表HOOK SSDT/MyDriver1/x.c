#include "SsdtHook.h"

VOID PageProtectOff()
{
	ULONG_PTR cr0;
	//__disable();										//�����ж�
	irql = KfRaiseIrql(HIGH_LEVEL);
	cr0 = __readcr0();									//��ȡcr0
	cr0 &= 0xfffffffffffeffff;							//��ҳд�뱣��λ��������
	__writecr0(cr0);									//д��cr0
}

VOID PageProtectOn()
{
	ULONG_PTR cr0;
	cr0 = __readcr0();									//��ȡcr0
	cr0 |= 0x10000;										//��ԭҳ����λ
	__writecr0(cr0);									//д��cr0
														//__enable();											//��������ж�����
	KeLowerIrql(irql);
}

NTSTATUS __fastcall MyNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
	HANDLE CurrentHandle;
	PEPROCESS CurrentProcess;
	NTSTATUS status;

	CurrentHandle = ClientId->UniqueProcess;

	status = PsLookupProcessByProcessId(CurrentHandle, &CurrentProcess);

	if (!NT_SUCCESS(status))
		return ((NTOPENPROCESS)(old_NtOpenProcess))(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

	KdPrint(("��Ҫ�򿪵Ľ����ǣ�%s\n", PsGetProcessImageFileName(CurrentProcess)));

	return ((NTOPENPROCESS)(old_NtOpenProcess))(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

ULONG_PTR GetSsdtBase()
{
	ULONG_PTR SystemCall64;								//��msr�ж�ȡ����SystemCall64�ĵ�ַ
	ULONG_PTR StartAddress;								//��Ѱ����ʼ��ַ����SystemCall64����ʼ��ַ
	ULONG_PTR EndAddress;								//��Ѱ���ս��ַ
	UCHAR *p;											//�����жϵ�������
	ULONG_PTR SsdtBase;									//SSDT��ַ

	SystemCall64 = __readmsr(0xC0000082);
	StartAddress = SystemCall64;
	EndAddress = StartAddress + 0x500;
	while (StartAddress < EndAddress)
	{
		p = (UCHAR*)StartAddress;
		if (MmIsAddressValid(p) && MmIsAddressValid(p + 1) && MmIsAddressValid(p + 2))
		{
			if (*p == 0x4c && *(p + 1) == 0x8d && *(p + 2) == 0x15)
			{
				HookAddress = StartAddress;
				SsdtBase = (ULONG_PTR)(*(ULONG*)(p + 3)) + (ULONG_PTR)(p + 7);
				ShadowSSDTAddress = (ULONG_PTR)(*(ULONG*)(p + 10) + (ULONG_PTR)(p + 14));
				break;
			}
		}
		++StartAddress;
	}

	return SsdtBase;
}

VOID StartHook()
{
	*(ULONG_PTR*)(MovCode + 2) = (ULONG_PTR)NewssdtTable;
	RtlCopyMemory((PVOID)JmpToOld, (PVOID)MovCode, sizeof(MovCode));
	MovCode[1] = '\xBB';
	*(ULONG_PTR*)(MovCode + 2) = (ULONG_PTR)(ShadowSSDTAddress);
	RtlCopyMemory((PVOID)(JmpToOld + sizeof(MovCode)), (PVOID)MovCode, sizeof(MovCode));
	*(ULONG_PTR*)(JmpCode + 6) = (ULONG_PTR)(HookAddress + 14);
	RtlCopyMemory((PVOID)(JmpToOld + sizeof(MovCode) + sizeof(MovCode)), (PVOID)JmpCode, sizeof(JmpCode));

	*(ULONG_PTR*)(JmpCode + 6) = (ULONG_PTR)JmpToOld;
	RtlCopyMemory((PVOID)OldCode, (PVOID)HookAddress, sizeof(OldCode));
	PageProtectOff();
	RtlCopyMemory((PVOID)HookAddress, (PVOID)JmpCode, sizeof(JmpCode));
	PageProtectOn();
}

PKPROCESS GetCsrss()
{
	ULONG i;
	PEPROCESS CurrentProcess;

	for (i = 0; i < 0x10000; i += 4)
	{
		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)i, &CurrentProcess)))
			continue;
		else
		{
			if (strstr(PsGetProcessImageFileName(CurrentProcess), "csrss"))
			{
				ObDereferenceObject(CurrentProcess);
				return CurrentProcess;
			}
			else
			{
				ObDereferenceObject(CurrentProcess);
				continue;
			}
		}
	}
	return NULL;
}

VOID Init()
{
	PSYSTEM_SERVICE_TABLE SsdtInfo;

	PSYSTEM_SERVICE_TABLE TempServiceInfo;

	PUCHAR NewFuncAddress;

	ULONG Offset;

	ULONG_PTR i;								//����ѭ����ֵ

	PKPROCESS Csrss;

	KAPC_STATE ApcState;

	SsdtInfo = (PSYSTEM_SERVICE_TABLE)GetSsdtBase();

	/*һ��SSDT���������������SST��SSDT�ĵڶ���SSTΪ�ա�Shadow SSDT�ĵڶ���SST����shadow sst*/
	NewssdtTable = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, sizeof(SYSTEM_SERVICE_TABLE) + sizeof(SYSTEM_SERVICE_TABLE) + SsdtInfo->NumberOfServices * 4 + SsdtInfo->NumberOfServices * 14, 'ytz');
	if (NewssdtTable == NULL)
	{
		KdPrint(("�����µ�SSDT�ڴ�ʧ�ܣ�\n"));
		return;
	}
	RtlZeroMemory(NewssdtTable, sizeof(SYSTEM_SERVICE_TABLE) + sizeof(SYSTEM_SERVICE_TABLE) + SsdtInfo->NumberOfServices * 4 + SsdtInfo->NumberOfServices * 14);
	OldssdtFuncAddress = (PULONG_PTR)ExAllocatePoolWithTag(NonPagedPool, SsdtInfo->NumberOfServices * 8, 'ytz');
	if (OldssdtFuncAddress == NULL)
	{
		KdPrint(("����ɵ�SSDT������ַ����ʧ�ܣ�\n"));
		return;
	}
	RtlZeroMemory(OldssdtFuncAddress, SsdtInfo->NumberOfServices * 8);
	JmpToOld = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, sizeof(JmpCode) + sizeof(MovCode) + sizeof(MovCode), 'ytz');
	if (JmpToOld == NULL)
	{
		KdPrint(("����ShellCode�ڴ�ʧ�ܣ�\n"));
		return;
	}
	RtlZeroMemory(JmpToOld, sizeof(JmpCode) + sizeof(MovCode) + sizeof(MovCode));

	NewFuncAddress = (PUCHAR)(NewssdtTable + sizeof(SYSTEM_SERVICE_TABLE) + sizeof(SYSTEM_SERVICE_TABLE) + SsdtInfo->NumberOfServices * 4);

	TempServiceInfo = (PSYSTEM_SERVICE_TABLE)NewssdtTable;

	TempServiceInfo->ServiceCounterTableBase = 0;
	TempServiceInfo->ServiceTableBase = (PULONG)(NewssdtTable + sizeof(SYSTEM_SERVICE_TABLE) + sizeof(SYSTEM_SERVICE_TABLE));
	TempServiceInfo->NumberOfServices = SsdtInfo->NumberOfServices;
	TempServiceInfo->ParamTableBase = NULL;

	for (i = 0; i < SsdtInfo->NumberOfServices; ++i)
	{
		Offset = SsdtInfo->ServiceTableBase[i];
		Offset = Offset >> 4;
		OldssdtFuncAddress[i] = (ULONG_PTR)((ULONG_PTR)SsdtInfo->ServiceTableBase + (ULONG_PTR)Offset);
		OldssdtFuncAddress[i] = OldssdtFuncAddress[i] & 0xFFFFFFFF0FFFFFFF;									//���ﴦ����ֱ�ӼӵĽ�λ����
		*(ULONG_PTR*)(JmpCode + 6) = OldssdtFuncAddress[i];
		RtlCopyMemory((PVOID)(NewFuncAddress + i * 14), (PVOID)JmpCode, sizeof(JmpCode));
	}

	for (i = 0; i < SsdtInfo->NumberOfServices; ++i)
	{
		Offset = (ULONG)((ULONG_PTR)(NewFuncAddress + i * 14) - (ULONG_PTR)TempServiceInfo->ServiceTableBase);
		Offset = Offset << 4;
		Offset |= (SsdtInfo->ServiceTableBase[i] & 0xF);													//������Ϊ�˻�ȡĩ4λֵ�����ֵ�����ŵ�ǰ�����Ĳ�������
		TempServiceInfo->ServiceTableBase[i] = Offset;
	}

	old_NtOpenProcess = OldssdtFuncAddress[IndexOfNtOpenProcess];
	*(ULONG_PTR*)(JmpCode + 6) = (ULONG_PTR)MyNtOpenProcess;
	RtlCopyMemory((PVOID)(NewFuncAddress + IndexOfNtOpenProcess * 14), (PVOID)JmpCode, sizeof(JmpCode));

	Csrss = GetCsrss();

	KeStackAttachProcess(Csrss, &ApcState);

	PageProtectOff();

	OldShadowServiceTableBase = (ULONG_PTR)((PSYSTEM_SERVICE_TABLE)ShadowSSDTAddress)->ServiceTableBase;

	((PSYSTEM_SERVICE_TABLE)ShadowSSDTAddress)->ServiceTableBase = TempServiceInfo->ServiceTableBase;

	PageProtectOn();

	KeUnstackDetachProcess(&ApcState);

	StartHook();
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	PKPROCESS Csrss;
	KAPC_STATE ApcState;

	Csrss = GetCsrss();

	KeStackAttachProcess(Csrss, &ApcState);
	PageProtectOff();
	((PSYSTEM_SERVICE_TABLE)ShadowSSDTAddress)->ServiceTableBase = (PULONG)OldShadowServiceTableBase;
	PageProtectOn();
	KeUnstackDetachProcess(&ApcState);

	PageProtectOff();
	RtlCopyMemory((PVOID)HookAddress, (PVOID)OldCode, sizeof(OldCode));
	PageProtectOn();

	ExFreePoolWithTag(OldssdtFuncAddress, 'ytz');
	ExFreePoolWithTag(NewssdtTable, 'ytz');
	ExFreePoolWithTag(JmpToOld, 'ytz');

	KdPrint(("Unload Success!\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegString)
{
	KdPrint(("Entry Driver!\n"));
	Init();
	DriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;
}