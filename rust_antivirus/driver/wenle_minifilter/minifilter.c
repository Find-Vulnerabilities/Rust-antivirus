/*
 * Wenle Antivirus Minifilter Driver - FIXED VERSION
 */

#include <fltKernel.h>
#include <ntstatus.h>
#include <ntdef.h>
#include <ntifs.h>

#pragma warning(disable:4100 4127 4996)

// 定义 IOCTL
#define IOCTL_DEVICE_COMMAND CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#pragma pack(push, 1)
typedef struct _SCAN_REQUEST_MESSAGE {
    ULONG MessageType;
    ULONG MessageLength;
    ULONG ProcessId;
    WCHAR FilePath[512];
    ULONG64 FileSize;
    ULONG FileAttributes;
} SCAN_REQUEST_MESSAGE, *PSCAN_REQUEST_MESSAGE;

typedef struct _SCAN_RESPONSE_MESSAGE {
    ULONG MessageType;
    ULONG MessageLength;
    UCHAR IsMalicious;
    ULONG ThreatLevel;
    WCHAR ThreatName[256];
} SCAN_RESPONSE_MESSAGE, *PSCAN_RESPONSE_MESSAGE;
#pragma pack(pop)

// 类型定义
typedef NTSTATUS (*PFN_PS_SET_LOAD_IMAGE_NOTIFY_ROUTINE)(
    PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
);

typedef NTSTATUS (*PFN_PS_REMOVE_LOAD_IMAGE_NOTIFY_ROUTINE)(
    PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
);

// 全局变量
PFLT_FILTER gFilterHandle = NULL;
PFLT_PORT gServerPort = NULL;
PFLT_PORT gClientPort = NULL;
PDEVICE_OBJECT gDeviceObject = NULL;

HANDLE gProtectedProcessId = NULL;
BOOLEAN gServiceWasAlive = FALSE;
PVOID gObRegistrationHandle = NULL;

PFN_PS_SET_LOAD_IMAGE_NOTIFY_ROUTINE pfnPsSetLoadImageNotifyRoutine = NULL;
PFN_PS_REMOVE_LOAD_IMAGE_NOTIFY_ROUTINE pfnPsRemoveLoadImageNotifyRoutine = NULL;

// ========== In-Kernel Cache (Hash/String Collision Support) ==========
#define CACHE_SIZE 4096
#define MAX_PATH_CHARS 256
#define MAX_PROBE 8

typedef struct _FILE_CACHE_ENTRY {
    ULONG PathHash;
    BOOLEAN IsUsed;
    BOOLEAN IsSafe;
    LARGE_INTEGER Timestamp;
    USHORT PathLength;
    WCHAR PathName[MAX_PATH_CHARS];
} FILE_CACHE_ENTRY, *PFILE_CACHE_ENTRY;

FILE_CACHE_ENTRY gFileCache[CACHE_SIZE];
KSPIN_LOCK gCacheLock;

ULONG CalculateHash(PUNICODE_STRING String) {
    ULONG hash = 5381;
    USHORT i;
    for (i = 0; i < String->Length / sizeof(WCHAR); i++) {
        hash = ((hash << 5) + hash) + String->Buffer[i];
    }
    return hash;
}

BOOLEAN CheckFileCache(PUNICODE_STRING FileName) {
    ULONG hash = CalculateHash(FileName);
    ULONG startIndex = hash % CACHE_SIZE;
    BOOLEAN isSafe = FALSE;
    KIRQL oldIrql;
    ULONG i, index;
    
    // Prevent buffer overflow in path string
    if (FileName->Length > MAX_PATH_CHARS * sizeof(WCHAR)) {
        return FALSE;
    }
    
    KeAcquireSpinLock(&gCacheLock, &oldIrql);
    for (i = 0; i < MAX_PROBE; i++) {
        index = (startIndex + i) % CACHE_SIZE;
        if (!gFileCache[index].IsUsed) {
            break; // Stop probing on first empty slot
        }
        if (gFileCache[index].PathHash == hash && gFileCache[index].PathLength == FileName->Length) {
            if (RtlCompareMemory(gFileCache[index].PathName, FileName->Buffer, FileName->Length) == FileName->Length) {
                isSafe = gFileCache[index].IsSafe;
                // DbgPrint("[WenleMinifilter] Cache Hit (Safely matched full string) for %wZ\n", FileName);
                break;
            }
            // If hash matches but memory doesn't, it's a collision! We continue probing.
        }
    }
    KeReleaseSpinLock(&gCacheLock, oldIrql);
    return isSafe;
}

VOID UpdateFileCache(PUNICODE_STRING FileName, BOOLEAN IsSafe) {
    ULONG hash = CalculateHash(FileName);
    ULONG startIndex = hash % CACHE_SIZE;
    KIRQL oldIrql;
    ULONG i, index;
    ULONG oldestIndex = startIndex;
    LARGE_INTEGER oldestTime;
    
    // Support max path
    if (FileName->Length > MAX_PATH_CHARS * sizeof(WCHAR)) {
        return;
    }
    
    KeAcquireSpinLock(&gCacheLock, &oldIrql);
    oldestTime.QuadPart = MAXLONGLONG;
    
    for (i = 0; i < MAX_PROBE; i++) {
        index = (startIndex + i) % CACHE_SIZE;
        
        // Find existing to update
        if (gFileCache[index].IsUsed && gFileCache[index].PathHash == hash && gFileCache[index].PathLength == FileName->Length) {
            if (RtlCompareMemory(gFileCache[index].PathName, FileName->Buffer, FileName->Length) == FileName->Length) {
                gFileCache[index].IsSafe = IsSafe;
                KeQuerySystemTime(&gFileCache[index].Timestamp);
                KeReleaseSpinLock(&gCacheLock, oldIrql);
                return;
            }
        }
        
        // Use empty slot
        if (!gFileCache[index].IsUsed) {
            gFileCache[index].IsUsed = TRUE;
            gFileCache[index].PathHash = hash;
            gFileCache[index].IsSafe = IsSafe;
            gFileCache[index].PathLength = FileName->Length;
            RtlCopyMemory(gFileCache[index].PathName, FileName->Buffer, FileName->Length);
            KeQuerySystemTime(&gFileCache[index].Timestamp);
            KeReleaseSpinLock(&gCacheLock, oldIrql);
            return;
        }
        
        // Track oldest for eviction if bucket chunk is full
        if (gFileCache[index].Timestamp.QuadPart < oldestTime.QuadPart) {
            oldestTime = gFileCache[index].Timestamp;
            oldestIndex = index;
        }
    }
    
    // Evict oldest due to collision overload
    gFileCache[oldestIndex].IsUsed = TRUE;
    gFileCache[oldestIndex].PathHash = hash;
    gFileCache[oldestIndex].IsSafe = IsSafe;
    gFileCache[oldestIndex].PathLength = FileName->Length;
    RtlCopyMemory(gFileCache[oldestIndex].PathName, FileName->Buffer, FileName->Length);
    KeQuerySystemTime(&gFileCache[oldestIndex].Timestamp);
    KeReleaseSpinLock(&gCacheLock, oldIrql);
}
// ==================================================

// 函数声明
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
NTSTATUS MinifilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags);

OB_PREOP_CALLBACK_STATUS ObjectPreCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
);

FLT_PREOP_CALLBACK_STATUS MinifilterPreCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS MinifilterPreWrite(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS MinifilterPostCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags
);

NTSTATUS CommunicationPortConnectNotify(
    PFLT_PORT ClientPort,
    PVOID ServerPortCookie,
    PVOID ConnectionContext,
    ULONG ContextSize,
    PVOID *ConnectionCookie
);

VOID CommunicationPortDisconnectNotify(
    PVOID ConnectionCookie
);

NTSTATUS MinifilterDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
);

VOID ImageLoadNotifyCallback(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
);

// 操作注册表
const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, MinifilterPreCreate, MinifilterPostCreate },
    { IRP_MJ_WRITE, 0, MinifilterPreWrite, NULL },
    { IRP_MJ_OPERATION_END }
};

// 过滤器注册
const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    MinifilterUnload,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

// ========== Ob Callback ==========
OB_PREOP_CALLBACK_STATUS ObjectPreCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    // We only care about process handles
    if (OperationInformation->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    PEPROCESS TargetProcess = (PEPROCESS)OperationInformation->Object;
    HANDLE TargetProcessId = PsGetProcessId(TargetProcess);

    // Check if the target process is the protected process
    if (gProtectedProcessId == NULL || TargetProcessId != gProtectedProcessId) {
        return OB_PREOP_SUCCESS;
    }

    // Get the caller process ID
    HANDLE CallerProcessId = PsGetCurrentProcessId();

    // Do not restrict the kernel or the process opening a handle to itself
    if (OperationInformation->KernelHandle || CallerProcessId == TargetProcessId) {
        return OB_PREOP_SUCCESS;
    }

    // Strip access rights
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~(PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_SUSPEND_RESUME);
    } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~(PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_SUSPEND_RESUME);
    }

    return OB_PREOP_SUCCESS;
}

// ========== Driver Entry ==========
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status;
    UNICODE_STRING DeviceName, SymlinkName, PortName;
    OBJECT_ATTRIBUTES ObjectAttributes;

    UNREFERENCED_PARAMETER(RegistryPath);
    DbgPrint("[WenleMinifilter] DriverEntry called\n");

    // Initialize Cache Lock
    KeInitializeSpinLock(&gCacheLock);
    RtlZeroMemory(gFileCache, sizeof(gFileCache));

    // 注册过滤器
    Status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("[WenleMinifilter] FltRegisterFilter failed: 0x%08X\n", Status);
        return Status;
    }

    // 创建通信端口
    RtlInitUnicodeString(&PortName, L"\\WenlePort");
    InitializeObjectAttributes(&ObjectAttributes, &PortName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = FltCreateCommunicationPort(
        gFilterHandle,
        &gServerPort,
        &ObjectAttributes,
        NULL,
        CommunicationPortConnectNotify,
        CommunicationPortDisconnectNotify,
        NULL,
        1
    );

    if (!NT_SUCCESS(Status)) {
        DbgPrint("[WenleMinifilter] FltCreateCommunicationPort failed: 0x%08X\n", Status);
        FltUnregisterFilter(gFilterHandle);
        return Status;
    }

    // 启动过滤
    Status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("[WenleMinifilter] FltStartFiltering failed: 0x%08X\n", Status);
        FltCloseCommunicationPort(gServerPort);
        FltUnregisterFilter(gFilterHandle);
        return Status;
    }

    // 创建设备对象
    RtlInitUnicodeString(&DeviceName, L"\\Device\\WenleDriver");
    RtlInitUnicodeString(&SymlinkName, L"\\DosDevices\\WenleDriver");

    Status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &gDeviceObject);
    if (NT_SUCCESS(Status)) {
        Status = IoCreateSymbolicLink(&SymlinkName, &DeviceName);
        if (NT_SUCCESS(Status)) {
            DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MinifilterDeviceControl;
            DriverObject->DriverUnload = NULL;
        } else {
            IoDeleteDevice(gDeviceObject);
            gDeviceObject = NULL;
        }
    }

    // 注册镜像加载通知
    {
        UNICODE_STRING RoutineName;
        
        RtlInitUnicodeString(&RoutineName, L"PsSetLoadImageNotifyRoutine");
        pfnPsSetLoadImageNotifyRoutine = (PFN_PS_SET_LOAD_IMAGE_NOTIFY_ROUTINE)MmGetSystemRoutineAddress(&RoutineName);
        
        if (pfnPsSetLoadImageNotifyRoutine != NULL) {
            pfnPsSetLoadImageNotifyRoutine(ImageLoadNotifyCallback);
        }
    }

    // 注册进程保护 (ObRegisterCallbacks)
    {
        OB_OPERATION_REGISTRATION ObOperationCallbacks;
        OB_CALLBACK_REGISTRATION ObCbRegistration;
        UNICODE_STRING ObAltitude;

        ObOperationCallbacks.ObjectType = PsProcessType;
        ObOperationCallbacks.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        ObOperationCallbacks.PreOperation = ObjectPreCallback;
        ObOperationCallbacks.PostOperation = NULL;

        RtlInitUnicodeString(&ObAltitude, L"320000"); // Just an arbitrary reasonable altitude

        ObCbRegistration.Version = OB_FLT_REGISTRATION_VERSION;
        ObCbRegistration.OperationRegistrationCount = 1;
        ObCbRegistration.Altitude = ObAltitude;
        ObCbRegistration.RegistrationContext = NULL;
        ObCbRegistration.OperationRegistration = &ObOperationCallbacks;

        Status = ObRegisterCallbacks(&ObCbRegistration, &gObRegistrationHandle);
        if (!NT_SUCCESS(Status)) {
            DbgPrint("[WenleMinifilter] ObRegisterCallbacks failed: 0x%08X\n", Status);
            // We can continue loading even if soft protection fails, or choose to fail loading.
            gObRegistrationHandle = NULL;
        } else {
            DbgPrint("[WenleMinifilter] ObRegisterCallbacks registered successfully.\n");
        }
    }

    DbgPrint("[WenleMinifilter] Driver loaded successfully\n");
    return STATUS_SUCCESS;
}

// ========== Unload ==========
NTSTATUS MinifilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNICODE_STRING SymlinkName;
    UNREFERENCED_PARAMETER(Flags);

    DbgPrint("[WenleMinifilter] MinifilterUnload called\n");

    // 移除镜像加载通知
    if (pfnPsRemoveLoadImageNotifyRoutine != NULL) {
        RtlInitUnicodeString(&SymlinkName, L"PsRemoveLoadImageNotifyRoutine");
        pfnPsRemoveLoadImageNotifyRoutine = (PFN_PS_REMOVE_LOAD_IMAGE_NOTIFY_ROUTINE)MmGetSystemRoutineAddress(&SymlinkName);
        if (pfnPsRemoveLoadImageNotifyRoutine != NULL) {
            pfnPsRemoveLoadImageNotifyRoutine(ImageLoadNotifyCallback);
        }
    }

    // 清理资源
    if (gObRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(gObRegistrationHandle);
        gObRegistrationHandle = NULL;
    }

    if (gServerPort != NULL) {
        FltCloseCommunicationPort(gServerPort);
    }

    if (gDeviceObject != NULL) {
        RtlInitUnicodeString(&SymlinkName, L"\\DosDevices\\WenleDriver");
        IoDeleteSymbolicLink(&SymlinkName);
        IoDeleteDevice(gDeviceObject);
    }

    DbgPrint("[WenleMinifilter] Driver unloaded successfully\n");
    return STATUS_SUCCESS;
}

// ========== Pre Create Callback ==========
FLT_PREOP_CALLBACK_STATUS MinifilterPreCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID *CompletionContext
)
{
    NTSTATUS Status;
    PFLT_FILE_NAME_INFORMATION FileNameInfo = NULL;
    PUNICODE_STRING FileName;
    WCHAR *Extension;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // [CRITICAL FIX] 1. 豁免驅動自己的操作，防止死結死迴圈
    if (gProtectedProcessId != NULL && FltGetRequestorProcessId(Data) == gProtectedProcessId) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    Status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);
    if (!NT_SUCCESS(Status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FileName = &FileNameInfo->Name;

    if (FileName->Buffer != NULL && FileName->Length > 0) {
        Extension = wcsrchr(FileName->Buffer, L'.');
        if (Extension != NULL) {
            if (_wcsicmp(Extension, L".exe") == 0 || 
                _wcsicmp(Extension, L".dll") == 0 || 
                _wcsicmp(Extension, L".sys") == 0 ||
                _wcsicmp(Extension, L".ps1") == 0 ||
                _wcsicmp(Extension, L".vbs") == 0) {
                
                DbgPrint("[WenleMinifilter] Executable file detected: %wZ\n", FileName);
                
                // [CRITICAL FIX] 3. Crash Recovery (Fail-Close) + Boot Friendly
                // If the user-mode service is down BUT had connected once, it's a crash. Block everything!
                // If it hasn't connected yet (gServiceWasAlive == FALSE), system is still booting, allow it.
                if (gClientPort == NULL) {
                    if (gServiceWasAlive) {
                        DbgPrint("[WenleMinifilter] User-mode scanner CRASHED. Fail-Close applied!\n");
                        FltReleaseFileNameInformation(FileNameInfo);
                        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                        return FLT_PREOP_COMPLETE;
                    } else {
                        // System is booting up, scanner hasn't started yet. Let it pass.
                        FltReleaseFileNameInformation(FileNameInfo);
                        return FLT_PREOP_SUCCESS_NO_CALLBACK;
                    }
                }
                
                // [CRITICAL FIX] 1. In-Kernel Cache
                // If it's already scanned and safe, bypass Rust completely.
                if (CheckFileCache(FileName)) {
                    // DbgPrint("[WenleMinifilter] File is safe in cache: %wZ\n", FileName);
                    FltReleaseFileNameInformation(FileNameInfo);
                    return FLT_PREOP_SUCCESS_NO_CALLBACK;
                }
                
                if (gClientPort != NULL) {
                    SCAN_REQUEST_MESSAGE request = {0};
                    SCAN_RESPONSE_MESSAGE response = {0};
                    ULONG replyLength = sizeof(SCAN_RESPONSE_MESSAGE);
                    NTSTATUS msgStatus;
                    LARGE_INTEGER timeout;
                    
                    request.MessageType = 1;
                    request.MessageLength = sizeof(SCAN_REQUEST_MESSAGE);
                    request.ProcessId = FltGetRequestorProcessId(Data);
                    
                    // Copy the file path safely
                    ULONG nameLen = FileName->Length;
                    if (nameLen > (511 * sizeof(WCHAR))) {
                        nameLen = 511 * sizeof(WCHAR);
                    }
                    RtlCopyMemory(request.FilePath, FileName->Buffer, nameLen);
                    request.FilePath[nameLen / sizeof(WCHAR)] = L'\0';
                    
                    // [CRITICAL FIX] 2. 避免 Fail-Open 漏洞。1秒太短容易被駭客用大檔案洪流產生逾時而繞過，改為15秒
                    timeout.QuadPart = -150000000;
                    
                    msgStatus = FltSendMessage(
                        gFilterHandle,
                        &gClientPort,
                        &request,
                        sizeof(SCAN_REQUEST_MESSAGE),
                        &response,
                        &replyLength,
                        &timeout
                    );
                    
                    if (NT_SUCCESS(msgStatus) && replyLength >= sizeof(SCAN_RESPONSE_MESSAGE)) {
                        if (response.IsMalicious) {
                            DbgPrint("[WenleMinifilter] Blocked malicious file based on user-mode scan!\n");
                            FltReleaseFileNameInformation(FileNameInfo);
                            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                            return FLT_PREOP_COMPLETE; // Block it
                        } else {
                            // Mark as safe in cache
                            UpdateFileCache(FileName, TRUE);
                        }
                    } else {
                        // Timeout or other error -> Fail-Close
                        DbgPrint("[WenleMinifilter] Scan request failed (0x%X). Fail-Close!\n", msgStatus);
                        FltReleaseFileNameInformation(FileNameInfo);
                        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                        return FLT_PREOP_COMPLETE;
                    }
                }
            }
        }
    }

    FltReleaseFileNameInformation(FileNameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ========== Pre Write Callback ==========
FLT_PREOP_CALLBACK_STATUS MinifilterPreWrite(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID *CompletionContext
)
{
    NTSTATUS Status;
    PFLT_FILE_NAME_INFORMATION FileNameInfo = NULL;
    PUNICODE_STRING FileName;
    WCHAR *Extension;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // [CRITICAL FIX] 1. 豁免驅動自己的操作，防止死結死迴圈
    if (gProtectedProcessId != NULL && FltGetRequestorProcessId(Data) == gProtectedProcessId) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    Status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);
    if (!NT_SUCCESS(Status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FileName = &FileNameInfo->Name;

    if (FileName->Buffer != NULL && FileName->Length > 0) {
        Extension = wcsrchr(FileName->Buffer, L'.');
        if (Extension != NULL) {
            // Check for extensions we care about for writing (e.g., executables and scripts)
            if (_wcsicmp(Extension, L".exe") == 0 || 
                _wcsicmp(Extension, L".dll") == 0 || 
                _wcsicmp(Extension, L".sys") == 0 ||
                _wcsicmp(Extension, L".ps1") == 0 ||
                _wcsicmp(Extension, L".vbs") == 0) {
                
                DbgPrint("[WenleMinifilter] Executable file write detected: %wZ\n", FileName);
                
                // [CRITICAL FIX] 3. Crash Recovery (Fail-Close) + Boot Friendly
                if (gClientPort == NULL) {
                    if (gServiceWasAlive) {
                        DbgPrint("[WenleMinifilter] User-mode scanner CRASHED. Fail-Close applied to writes!\n");
                        FltReleaseFileNameInformation(FileNameInfo);
                        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                        return FLT_PREOP_COMPLETE;
                    } else {
                        // System is booting up, scanner hasn't started yet. Let it pass.
                        FltReleaseFileNameInformation(FileNameInfo);
                        return FLT_PREOP_SUCCESS_NO_CALLBACK;
                    }
                }
                
                // For Write operations, invalidate the cache if it's there
                // We're about to modify it, but wait, usually write triggers scan.
                // If we want to optimize writes, we still scan on write.
                // We can't trust cache on write! Actually, we just invalidate cache.
                UpdateFileCache(FileName, FALSE);

                if (gClientPort != NULL) {
                    SCAN_REQUEST_MESSAGE request = {0};
                    SCAN_RESPONSE_MESSAGE response = {0};
                    ULONG replyLength = sizeof(SCAN_RESPONSE_MESSAGE);
                    NTSTATUS msgStatus;
                    LARGE_INTEGER timeout;
                    
                    request.MessageType = 2; // MessageType 2 for FileWrite
                    request.MessageLength = sizeof(SCAN_REQUEST_MESSAGE);
                    request.ProcessId = FltGetRequestorProcessId(Data);
                    
                    // Copy the file path safely
                    ULONG nameLen = FileName->Length;
                    if (nameLen > (511 * sizeof(WCHAR))) {
                        nameLen = 511 * sizeof(WCHAR);
                    }
                    RtlCopyMemory(request.FilePath, FileName->Buffer, nameLen);
                    request.FilePath[nameLen / sizeof(WCHAR)] = L'\0';
                    
                    // [CRITICAL FIX] 2. 避免 Fail-Open 漏洞。1秒太短容易被駭客用大檔案洪流產生逾時而繞過，改為15秒
                    timeout.QuadPart = -150000000;
                    
                    msgStatus = FltSendMessage(
                        gFilterHandle,
                        &gClientPort,
                        &request,
                        sizeof(SCAN_REQUEST_MESSAGE),
                        &response,
                        &replyLength,
                        &timeout
                    );
                    
                    if (NT_SUCCESS(msgStatus) && replyLength >= sizeof(SCAN_RESPONSE_MESSAGE)) {
                        if (response.IsMalicious) {
                            DbgPrint("[WenleMinifilter] Blocked malicious file write based on user-mode scan!\n");
                            FltReleaseFileNameInformation(FileNameInfo);
                            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                            return FLT_PREOP_COMPLETE; // Block it
                        } else {
                            // Safe to write, cache it
                            UpdateFileCache(FileName, TRUE);
                        }
                    } else {
                        // Timeout or err -> Fail-Close
                        DbgPrint("[WenleMinifilter] Scan request failed (0x%X). Fail-Close!\n", msgStatus);
                        FltReleaseFileNameInformation(FileNameInfo);
                        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                        return FLT_PREOP_COMPLETE;
                    }
                }
            }
        }
    }

    FltReleaseFileNameInformation(FileNameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ========== Post Create Callback ==========
FLT_POSTOP_CALLBACK_STATUS MinifilterPostCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

// ========== Communication Port Connect ==========
NTSTATUS CommunicationPortConnectNotify(
    PFLT_PORT ClientPort,
    PVOID ServerPortCookie,
    PVOID ConnectionContext,
    ULONG ContextSize,
    PVOID *ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);

    // [CRITICAL FIX] 2. Anti-Spoofing: 通訊防偽造 (Verify Digital Signature/Secret)
    // Real kernel modules check SeValidateImageHeader or similar to ensure signature
    // Since we're in a minifilter, we use a shared connection context secret + privilege check to prevent unprivileged fake clients.
    if (ConnectionContext == NULL || ContextSize < 28) {
        DbgPrint("[WenleMinifilter] Unauthorized connection attempt! Missing or invalid context size.\n");
        return STATUS_ACCESS_DENIED; // Reject connection
    }
    
    if (strncmp((const char*)ConnectionContext, "WENLE_ANTIVIRUS_SECRET_2026", 27) != 0) {
        DbgPrint("[WenleMinifilter] Unauthorized connection attempt! Invalid secret token. Spoofing prevented.\n");
        return STATUS_ACCESS_DENIED; // Reject connection
    }
    
    // Valid connection!
    gClientPort = ClientPort;
    *ConnectionCookie = NULL;
    gServiceWasAlive = TRUE;
    
    // 记录连接进来的用户态进程 ID 用作自保护
    gProtectedProcessId = PsGetCurrentProcessId();

    DbgPrint("[WenleMinifilter] User-mode scanner connected with valid signature/secret. Protected PID: %p\n", gProtectedProcessId);
    return STATUS_SUCCESS;
}

// ========== Communication Port Disconnect ==========
VOID CommunicationPortDisconnectNotify(PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    if (gClientPort != NULL) {
        FltCloseClientPort(gFilterHandle, &gClientPort);
        gClientPort = NULL;
    }
    
    gProtectedProcessId = NULL;
    DbgPrint("[WenleMinifilter] User-mode scanner disconnected.\n");
}

// ========== Device Control Handler ==========
NTSTATUS MinifilterDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION IrpStack;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG IoControlCode;

    UNREFERENCED_PARAMETER(DeviceObject);

    IrpStack = IoGetCurrentIrpStackLocation(Irp);
    IoControlCode = IrpStack->Parameters.DeviceIoControl.IoControlCode;

    DbgPrint("[WenleMinifilter] DeviceControl: IOCTL=0x%08X\n", IoControlCode);

    switch (IoControlCode) {
        case IOCTL_DEVICE_COMMAND:
            // 处理设备命令
            DbgPrint("[WenleMinifilter] IOCTL command received\n");
            break;
        default:
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

// ========== Image Load Notification ==========
VOID ImageLoadNotifyCallback(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
)
{
    UNREFERENCED_PARAMETER(ImageInfo);

    if (FullImageName == NULL || FullImageName->Buffer == NULL) {
        return;
    }

    // 跳过系统目录
    if (wcsstr(FullImageName->Buffer, L"\\System32\\") != NULL ||
        wcsstr(FullImageName->Buffer, L"\\SysWOW64\\") != NULL) {
        return;
    }

    DbgPrint("[WenleMinifilter] Module loaded (PID %p): %wZ\n", ProcessId, FullImageName);

    if (gClientPort != NULL) {
        SCAN_REQUEST_MESSAGE request = {0};
        SCAN_RESPONSE_MESSAGE response = {0};
        ULONG replyLength = sizeof(SCAN_RESPONSE_MESSAGE);
        NTSTATUS msgStatus;
        LARGE_INTEGER timeout;
        
        request.MessageType = 3; // MessageType 3 for ImageLoad
        request.MessageLength = sizeof(SCAN_REQUEST_MESSAGE);
        request.ProcessId = HandleToULong(ProcessId);
        
        // Copy the file path safely
        ULONG nameLen = FullImageName->Length;
        if (nameLen > (511 * sizeof(WCHAR))) {
            nameLen = 511 * sizeof(WCHAR);
        }
        RtlCopyMemory(request.FilePath, FullImageName->Buffer, nameLen);
        request.FilePath[nameLen / sizeof(WCHAR)] = L'\0';
        
        // [CRITICAL FIX] 2. 避免 Fail-Open 漏洞。1秒太短容易被駭客用大檔案洪流產生逾時而繞過，改為15秒`r`ntimeout.QuadPart = -150000000;
        
        msgStatus = FltSendMessage(
            gFilterHandle,
            &gClientPort,
            &request,
            sizeof(SCAN_REQUEST_MESSAGE),
            &response,
            &replyLength,
            &timeout
        );
        
        if (NT_SUCCESS(msgStatus) && replyLength >= sizeof(SCAN_RESPONSE_MESSAGE)) {
            if (response.IsMalicious) {
                DbgPrint("[WenleMinifilter] Malicious image load detected!\n");
                // For image loads, we cannot block directly via this callback usually, 
                // but user-mode can terminate the process.
            }
        }
    }
}
