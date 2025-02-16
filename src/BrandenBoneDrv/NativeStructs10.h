#pragma once

//
// Native structures W10 technical preview x64, build 9841
//
#pragma warning(disable : 4214 4201)
#pragma pack(push, 1)

//0x8 bytes (sizeof)
typedef struct _RTL_AVL_TREE
{
	struct _RTL_BALANCED_NODE* Root;                                        //0x0
} RTL_AVL_TREE, * PRTL_AVL_TREE, MM_AVL_TABLE, * PMM_AVL_TABLE;

//0x8 bytes (sizeof)
typedef struct _EX_PUSH_LOCK
{
	union
	{
		struct
		{
			ULONGLONG Locked : 1;                                             //0x0
			ULONGLONG Waiting : 1;                                            //0x0
			ULONGLONG Waking : 1;                                             //0x0
			ULONGLONG MultipleShared : 1;                                     //0x0
			ULONGLONG Shared : 60;                                            //0x0
		};
		ULONGLONG Value;                                                    //0x0
		VOID* Ptr;                                                          //0x0
	};
} _EX_PUSH_LOCK, * P_EX_PUSH_LOCK;

//0x8 bytes (sizeof)
typedef struct _EXHANDLE
{
	union
	{
		struct
		{
			ULONG TagBits : 2;                                                //0x0
			ULONG Index : 30;                                                 //0x0
		};
		VOID* GenericHandleOverlay;                                         //0x0
		ULONGLONG Value;                                                    //0x0
	};
} EXHANDLE, * PEXHANDLE;

//0x4 bytes (sizeof)
typedef struct _MMVAD_FLAGS
{
	union
	{
		struct
		{
			ULONG Lock : 1;                                                   //0x0
			ULONG LockContended : 1;                                          //0x0
			ULONG DeleteInProgress : 1;                                       //0x0
			ULONG NoChange : 1;                                               //0x0
			ULONG VadType : 3;                                                //0x0
			ULONG Protection : 5;                                             //0x0
			ULONG PreferredNode : 7;                                          //0x0
			ULONG PageSize : 2;                                               //0x0
			ULONG PrivateMemory : 1;                                          //0x0
		};
		ULONG EntireField;                                                  //0x0
	};
} _MMVAD_FLAGS, * PMMVAD_FLAGS;

/*
struct _MMVAD_FLAGS1 // Size=4
{
	unsigned long CommitCharge : 31; // Size=4 Offset=0 BitOffset=0 BitCount=31
	unsigned long MemCommit : 1; // Size=4 Offset=0 BitOffset=31 BitCount=1
};
*/

//0x4 bytes (sizeof)
typedef struct _MMVAD_FLAGS2
{
	union
	{
		struct
		{
			ULONG Large : 1;                                                  //0x0
			ULONG TrimBehind : 1;                                             //0x0
			ULONG Inherit : 1;                                                //0x0
			ULONG NoValidationNeeded : 1;                                     //0x0
			ULONG PrivateDemandZero : 1;                                      //0x0
			ULONG ImageMappingExtended : 1;                                   //0x0
			ULONG Spare : 26;                                                 //0x0
		};
		ULONG LongFlags;                                                    //0x0
	};
} _MMVAD_FLAGS2, * PMMVAD_FLAGS2;

//0x8 bytes (sizeof)
typedef struct _MI_VAD_SEQUENTIAL_INFO
{
	union
	{
		struct
		{
			ULONGLONG Length : 12;                                            //0x0
			ULONGLONG Vpn : 51;                                               //0x0
			ULONGLONG MustBeZero : 1;                                         //0x0
		};
		ULONGLONG EntireField;                                              //0x0
	};
} _MI_VAD_SEQUENTIAL_INFO, * PMI_VAD_SEQUENTIAL_INFO;

//0x4 bytes (sizeof)
typedef struct _MM_PRIVATE_VAD_FLAGS
{
	ULONG Lock : 1;                                                           //0x0
	ULONG LockContended : 1;                                                  //0x0
	ULONG DeleteInProgress : 1;                                               //0x0
	ULONG NoChange : 1;                                                       //0x0
	ULONG VadType : 3;                                                        //0x0
	ULONG Protection : 5;                                                     //0x0
	ULONG PreferredNode : 7;                                                  //0x0
	ULONG PageSize : 2;                                                       //0x0
	ULONG PrivateMemoryAlwaysSet : 1;                                         //0x0
	ULONG WriteWatch : 1;                                                     //0x0
	ULONG FixedLargePageSize : 1;                                             //0x0
	ULONG ZeroFillPagesOptional : 1;                                          //0x0
	ULONG MemCommit : 1;                                                      //0x0
	ULONG Graphics : 1;                                                       //0x0
	ULONG Enclave : 1;                                                        //0x0
	ULONG ShadowStack : 1;                                                    //0x0
	ULONG PhysicalMemoryPfnsReferenced : 1;                                   //0x0
} _MM_PRIVATE_VAD_FLAGS, * PMM_PRIVATE_VAD_FLAGS;

//0x4 bytes (sizeof)
typedef struct _MM_GRAPHICS_VAD_FLAGS
{
	ULONG Lock : 1;                                                           //0x0
	ULONG LockContended : 1;                                                  //0x0
	ULONG DeleteInProgress : 1;                                               //0x0
	ULONG NoChange : 1;                                                       //0x0
	ULONG VadType : 3;                                                        //0x0
	ULONG Protection : 5;                                                     //0x0
	ULONG PreferredNode : 7;                                                  //0x0
	ULONG PageSize : 2;                                                       //0x0
	ULONG PrivateMemoryAlwaysSet : 1;                                         //0x0
	ULONG WriteWatch : 1;                                                     //0x0
	ULONG FixedLargePageSize : 1;                                             //0x0
	ULONG ZeroFillPagesOptional : 1;                                          //0x0
	ULONG MemCommit : 1;                                                      //0x0
	ULONG GraphicsAlwaysSet : 1;                                              //0x0
	ULONG GraphicsUseCoherentBus : 1;                                         //0x0
	ULONG GraphicsNoCache : 1;                                                //0x0
	ULONG GraphicsPageProtection : 3;                                         //0x0
} _MM_GRAPHICS_VAD_FLAGS, * PMM_GRAPHICS_VAD_FLAGS;

//0x4 bytes (sizeof)
typedef struct _MM_SHARED_VAD_FLAGS
{
	ULONG Lock : 1;                                                           //0x0
	ULONG LockContended : 1;                                                  //0x0
	ULONG DeleteInProgress : 1;                                               //0x0
	ULONG NoChange : 1;                                                       //0x0
	ULONG VadType : 3;                                                        //0x0
	ULONG Protection : 5;                                                     //0x0
	ULONG PreferredNode : 7;                                                  //0x0
	ULONG PageSize : 2;                                                       //0x0
	ULONG PrivateMemoryAlwaysClear : 1;                                       //0x0
	ULONG PrivateFixup : 1;                                                   //0x0
	ULONG HotPatchState : 2;                                                  //0x0
} _MM_SHARED_VAD_FLAGS, * PMM_SHARED_VAD_FLAGS;

//0x40 bytes (sizeof)
typedef struct _MMVAD_SHORT
{
	union
	{
		struct
		{
			struct _MMVAD_SHORT* NextVad;                                   //0x0
			VOID* ExtraCreateInfo;                                          //0x8
		};
		struct _RTL_BALANCED_NODE VadNode;                                  //0x0
	};
	ULONG StartingVpn;                                                      //0x18
	ULONG EndingVpn;                                                        //0x1c
	UCHAR StartingVpnHigh;                                                  //0x20
	UCHAR EndingVpnHigh;                                                    //0x21
	UCHAR CommitChargeHigh;                                                 //0x22
	UCHAR SpareNT64VadUChar;                                                //0x23
	volatile LONG ReferenceCount;                                           //0x24
	struct _EX_PUSH_LOCK PushLock;                                          //0x28
	union
	{
		ULONG LongFlags;                                                    //0x30
		struct _MMVAD_FLAGS VadFlags;                                       //0x30
		struct _MM_PRIVATE_VAD_FLAGS PrivateVadFlags;                       //0x30
		struct _MM_GRAPHICS_VAD_FLAGS GraphicsVadFlags;                     //0x30
		struct _MM_SHARED_VAD_FLAGS SharedVadFlags;                         //0x30
		volatile ULONG VolatileVadLong;                                     //0x30
	} u;                                                                    //0x30
	ULONG CommitCharge;                                                     //0x34
	union
	{
		struct _MI_VAD_EVENT_BLOCK* EventList;                              //0x38
	} u5;                                                                   //0x38
} _MMVAD_SHORT, * PMMVAD_SHORT;

//0x88 bytes (sizeof)
typedef struct _MMVAD
{
	struct _MMVAD_SHORT Core;                                               //0x0
	struct _MMVAD_FLAGS2 VadFlags2;                                         //0x40
	struct _SUBSECTION* Subsection;                                         //0x48
	struct _MMPTE* FirstPrototypePte;                                       //0x50
	struct _MMPTE* LastContiguousPte;                                       //0x58
	struct _LIST_ENTRY ViewLinks;                                           //0x60
	struct _EPROCESS* VadsProcess;                                          //0x70
	union
	{
		struct _MI_VAD_SEQUENTIAL_INFO SequentialVa;                        //0x78
		struct _MMEXTEND_INFO* ExtendedInfo;                                //0x78
	} u4;                                                                   //0x78
	struct _FILE_OBJECT* FileObject;                                        //0x80
} MMVAD, * PMMVAD;
#pragma pack(pop)

//0x8 bytes (sizeof)
struct _HANDLE_TABLE_ENTRY_INFO
{
	ULONG AuditMask;                                                        //0x0
	ULONG MaxRelativeAccessMask;                                            //0x4
};

//0x10 bytes (sizeof)
typedef union _HANDLE_TABLE_ENTRY
{
	volatile LONGLONG VolatileLowValue;                                     //0x0
	LONGLONG LowValue;                                                      //0x0
	struct
	{
		struct _HANDLE_TABLE_ENTRY_INFO* volatile InfoTable;                //0x0
		LONGLONG HighValue;                                                     //0x8
		union _HANDLE_TABLE_ENTRY* NextFreeHandleEntry;                         //0x8
		struct _EXHANDLE LeafHandleValue;                                   //0x8
	};
	LONGLONG RefCountField;                                                 //0x0
	ULONGLONG Unlocked : 1;                                                   //0x0
	ULONGLONG RefCnt : 16;                                                    //0x0
	ULONGLONG Attributes : 3;                                                 //0x0
	struct
	{
		ULONGLONG ObjectPointerBits : 44;                                     //0x0
		ULONG GrantedAccessBits : 25;                                             //0x8
		ULONG NoRightsUpgrade : 1;                                                //0x8
		ULONG Spare1 : 6;                                                     //0x8
	};
	ULONG Spare2;                                                           //0xc
} _HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;

//0x40 bytes (sizeof)
struct _HANDLE_TABLE_FREE_LIST
{
	struct _EX_PUSH_LOCK FreeListLock;                                      //0x0
	union _HANDLE_TABLE_ENTRY* FirstFreeHandleEntry;                        //0x8
	union _HANDLE_TABLE_ENTRY* LastFreeHandleEntry;                         //0x10
	LONG HandleCount;                                                       //0x18
	ULONG HighWaterMark;                                                    //0x1c
};

//0x80 bytes (sizeof)
typedef struct _HANDLE_TABLE
{
	ULONG NextHandleNeedingPool;                                            //0x0
	LONG ExtraInfoPages;                                                    //0x4
	volatile ULONGLONG TableCode;                                           //0x8
	struct _EPROCESS* QuotaProcess;                                         //0x10
	struct _LIST_ENTRY HandleTableList;                                     //0x18
	ULONG UniqueProcessId;                                                  //0x28
	union
	{
		ULONG Flags;                                                        //0x2c
		struct
		{
			UCHAR StrictFIFO : 1;                                             //0x2c
			UCHAR EnableHandleExceptions : 1;                                 //0x2c
			UCHAR Rundown : 1;                                                //0x2c
			UCHAR Duplicated : 1;                                             //0x2c
			UCHAR RaiseUMExceptionOnInvalidHandleClose : 1;                   //0x2c
		};
	};
	struct _EX_PUSH_LOCK HandleContentionEvent;                             //0x30
	struct _EX_PUSH_LOCK HandleTableLock;                                   //0x38
	union
	{
		struct _HANDLE_TABLE_FREE_LIST FreeLists[1];                        //0x40
		struct
		{
			UCHAR ActualEntry[32];                                          //0x40
			struct _HANDLE_TRACE_DEBUG_INFO* DebugInfo;                     //0x60
		};
	};
} _HANDLE_TABLE, * PHANDLE_TABLE;

typedef struct _API_SET_VALUE_ENTRY_10
{
	ULONG Flags;
	ULONG NameOffset;
	ULONG NameLength;
	ULONG ValueOffset;
	ULONG ValueLength;
} API_SET_VALUE_ENTRY_10, * PAPI_SET_VALUE_ENTRY_10;

typedef struct _API_SET_VALUE_ARRAY_10
{
	ULONG Flags;
	ULONG NameOffset;
	ULONG Unk;
	ULONG NameLength;
	ULONG DataOffset;
	ULONG Count;
} API_SET_VALUE_ARRAY_10, * PAPI_SET_VALUE_ARRAY_10;

typedef struct _API_SET_NAMESPACE_ENTRY_10
{
	ULONG Limit;
	ULONG Size;
} API_SET_NAMESPACE_ENTRY_10, * PAPI_SET_NAMESPACE_ENTRY_10;

typedef struct _API_SET_NAMESPACE_ARRAY_10
{
	ULONG Version;
	ULONG Size;
	ULONG Flags;
	ULONG Count;
	ULONG Start;
	ULONG End;
	ULONG Unk[2];
} API_SET_NAMESPACE_ARRAY_10, * PAPI_SET_NAMESPACE_ARRAY_10;

#pragma warning(default : 4214 4201)

#define GET_VAD_ROOT(Table) Table->Root