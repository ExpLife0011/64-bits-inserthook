#pragma once
#ifndef SSDTHOOK_H
#define SSDTHOOK_H
#include <ntifs.h>
#include <ntddk.h>

#define IndexOfNtOpenProcess 35

typedef struct _SYSTEM_SERVICE_TABLE
{
	PULONG ServiceTableBase;
	PULONG ServiceCounterTableBase;
	UINT64 NumberOfServices;
	PUCHAR ParamTableBase;
}SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

typedef NTSTATUS(__fastcall *NTOPENPROCESS)(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
	);

NTSTATUS __fastcall MyNtOpenProcess(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
);

extern UCHAR *PsGetProcessImageFileName(PEPROCESS Process);

extern unsigned __int64 __readmsr(int register);				//��ȡmsr�Ĵ���

extern unsigned __int64 __readcr0(void);			//��ȡcr0��ֵ

extern void __writecr0(unsigned __int64 Data);		//д��cr0

extern void __debugbreak();							//�ϵ㣬����int 3

extern void __disable(void);						//�����ж�

extern void __enable(void);							//�����ж�

VOID PageProtectOff();

VOID PageProtectOn();

ULONG_PTR GetSsdtBase();							//��ȡSSDT��ַ

VOID StartHook();									//��ʼSSDT HOOK

PUCHAR NewssdtTable;								//ָ���µ�SSDT���ڲ������ĵ�ַ
PUCHAR JmpToOld;									//������ת��ShellCode
PULONG_PTR OldssdtFuncAddress;						//ÿһ��Ԫ�ض�������ԭ��SSDT���к����ĵ�ַ

UCHAR OldCode[14];									//�������溯��ԭ����ʮ�ĸ��ֽ�
UCHAR MovCode[] = { '\x49', '\xBA', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00' };		//����������mov r10��****��ԭ�����lea r10��ssdt�ĵ�ַ
UCHAR JmpCode[] = { '\xFF', '\x25', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00' };	//�������������Jmp��ת��

ULONG_PTR HookAddress;								//KiSystemCall64��HOOK�ĵ�
ULONG_PTR ShadowSSDTAddress;						//������ShadowSSDT�ĵ�ַ
ULONG_PTR OldShadowServiceTableBase;				//������Shadow SSDT�ĵ�һ��SST�ĵ�һ���ֵ
KIRQL irql;											//����IRQL

ULONG_PTR old_NtOpenProcess;

#endif

