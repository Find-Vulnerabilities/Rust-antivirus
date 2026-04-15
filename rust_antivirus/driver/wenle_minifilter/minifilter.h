/*
 * Wenle Antivirus Minifilter Driver - Header File (Schema v2.0)
 * Windows Kernel Minifilter for Real-time Threat Detection and Isolation
 */

#ifndef _WENLE_MINIFILTER_H_
#define _WENLE_MINIFILTER_H_

#include <fltKernel.h>
#include <ntstatus.h>
#include <ntdef.h>
#include <ntifs.h>

/* ===== Communication Protocol Definitions ===== */

// IOCTL codes for user-mode communication
#define IOCTL_SCAN_REQUEST             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_SCAN_RESPONSE            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_FILE_EVENT               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_BLOCK_PROCESS            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

// Communication port name
#define FILTER_PORT_NAME               L"\\WenleFilterPort"
#define DEVICE_NAME                    L"\\Device\\WenleDriver"
#define SYMBOLIC_LINK_NAME             L"\\DosDevices\\WenleDriver"

// Message type definitions
typedef enum _MESSAGE_TYPE {
    MsgTypeScanRequest = 1,
    MsgTypeScanResponse = 2,
    MsgTypeFileEvent = 3,
    MsgTypeBlockDecision = 4,
    MsgTypeShutdown = 5
} MESSAGE_TYPE;

// Maximum path length
#define MAX_PATH_LEN                   512
#define MAX_PROCESS_NAME_LEN           256
#define MAX_THREAT_NAME_LEN            128

// Event type definitions
typedef enum _FILE_EVENT_TYPE {
    EventTypeCreate = 1,
    EventTypeWrite = 2,
    EventTypeModify = 3,
    EventTypeDelete = 4
} FILE_EVENT_TYPE;

/* ===== Data Structure Definitions ===== */

// File event information sent to user-mode
typedef struct _FILE_EVENT_INFO {
    MESSAGE_TYPE MessageType;
    ULONG MessageSize;
    ULONG ProcessId;
    FILE_EVENT_TYPE EventType;
    ULONG FileSize;
    BOOLEAN IsExecutable;
    WCHAR FilePath[MAX_PATH_LEN];
    WCHAR ProcessName[MAX_PROCESS_NAME_LEN];
    LARGE_INTEGER Timestamp;
} FILE_EVENT_INFO, *PFILE_EVENT_INFO;

// Scan response from user-mode
typedef struct _SCAN_RESPONSE_INFO {
    MESSAGE_TYPE MessageType;
    ULONG MessageSize;
    BOOLEAN IsMalware;
    ULONG ThreatLevel;  // 0=safe, 1=warning, 2=danger, 3=critical
    WCHAR ThreatName[MAX_THREAT_NAME_LEN];
    BOOLEAN AllowExecution;
} SCAN_RESPONSE_INFO, *PSCAN_RESPONSE_INFO;

// Block decision
typedef struct _BLOCK_DECISION {
    MESSAGE_TYPE MessageType;
    ULONG MessageSize;
    ULONG ProcessId;
    BOOLEAN ShouldBlock;
    WCHAR Reason[MAX_THREAT_NAME_LEN];
} BLOCK_DECISION, *PBLOCK_DECISION;

// Scan request (internal)
typedef struct _SCAN_REQUEST {
    ULONG RequestId;
    WCHAR FilePath[MAX_PATH_LEN];
    ULONG ProcessId;
    FILE_EVENT_INFO EventInfo;
} SCAN_REQUEST, *PSCAN_REQUEST;

// Global driver context
typedef struct _DRIVER_CONTEXT {
    PFLT_FILTER FilterHandle;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;
    PDEVICE_OBJECT DeviceObject;
    KSPIN_LOCK PortLock;
    BOOLEAN Connected;
} DRIVER_CONTEXT, *PDRIVER_CONTEXT;

/* ===== Function Declarations ===== */

// Driver entry and unload
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
NTSTATUS MinifilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags);

// Minifilter callback functions
FLT_PREOP_CALLBACK_STATUS MinifilterPreCreate(
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

FLT_PREOP_CALLBACK_STATUS MinifilterPreWrite(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS MinifilterPostWrite(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags
);

// Communication callbacks
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

NTSTATUS CommunicationPortMessageNotify(
    PVOID PortCookie,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength,
    PULONG ReturnOutputBufferLength
);

// Device control
NTSTATUS MinifilterDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
);

// Utility functions
NTSTATUS SendFileEventToUserMode(
    PFLT_CALLBACK_DATA Data,
    FILE_EVENT_TYPE EventType
);

BOOLEAN IsExecutableFile(
    PFLT_FILE_NAME_INFORMATION FileNameInfo
);

NTSTATUS QueryAndApplyScanDecision(
    PFLT_CALLBACK_DATA Data,
    WCHAR *FilePath
);

#endif // _WENLE_MINIFILTER_H_
