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

extern unsigned __int64 __readmsr(int register);				//读取msr寄存器

extern unsigned __int64 __readcr0(void);			//读取cr0的值

extern void __writecr0(unsigned __int64 Data);		//写入cr0

extern void __debugbreak();							//断点，类似int 3

extern void __disable(void);						//屏蔽中断

extern void __enable(void);							//允许中断

VOID PageProtectOff();

VOID PageProtectOn();

ULONG_PTR GetSsdtBase();							//获取SSDT基址

VOID StartHook();									//开始SSDT HOOK

PUCHAR NewssdtTable;								//指向新的SSDT表内部函数的地址
PUCHAR JmpToOld;									//保存跳转的ShellCode
PULONG_PTR OldssdtFuncAddress;						//每一个元素都保存着原本SSDT表中函数的地址

UCHAR OldCode[14];									//用来保存函数原本的十四个字节
UCHAR MovCode[] = { '\x49', '\xBA', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00' };		//这条语句就是mov r10，****，原语句是lea r10，ssdt的地址
UCHAR JmpCode[] = { '\xFF', '\x25', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00' };	//这条语句是用来Jmp跳转的

ULONG_PTR HookAddress;								//KiSystemCall64被HOOK的点
ULONG_PTR ShadowSSDTAddress;						//保存着ShadowSSDT的地址
ULONG_PTR OldShadowServiceTableBase;				//保存着Shadow SSDT的第一个SST的第一项的值
KIRQL irql;											//保存IRQL

ULONG_PTR old_NtOpenProcess;

#endif

