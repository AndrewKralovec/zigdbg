const std = @import("std");
const windows = std.os.windows;

// Common COM types
pub const HRESULT = windows.HRESULT;
pub const GUID = windows.GUID;
pub const ULONG = windows.ULONG;
pub const ULONG64 = u64;
pub const PULONG64 = *u64;

// Debug status constants
pub const DEBUG_STATUS_NO_CHANGE = 0;
pub const DEBUG_STATUS_GO = 1;
pub const DEBUG_STATUS_GO_HANDLED = 2;
pub const DEBUG_STATUS_GO_NOT_HANDLED = 3;
pub const DEBUG_STATUS_STEP_OVER = 4;
pub const DEBUG_STATUS_STEP_INTO = 5;
pub const DEBUG_STATUS_BREAK = 6;
pub const DEBUG_STATUS_NO_DEBUGGEE = 7;
pub const DEBUG_STATUS_STEP_BRANCH = 8;
pub const DEBUG_STATUS_IGNORE_EVENT = 9;
pub const DEBUG_STATUS_RESTART_REQUESTED = 10;

// Debug create process options
pub const DEBUG_PROCESS_ONLY_THIS_PROCESS = 0x00000002;
pub const DEBUG_CREATE_PROCESS_NO_DEBUG_HEAP = 0x00000400;

// Debug attach flags
pub const DEBUG_ATTACH_NONINVASIVE = 0x00000001;
pub const DEBUG_ATTACH_EXISTING = 0x00000002;
pub const DEBUG_ATTACH_NONINVASIVE_NO_SUSPEND = 0x00000004;
pub const DEBUG_ATTACH_INVASIVE_NO_INITIAL_BREAK = 0x00000008;
pub const DEBUG_ATTACH_INVASIVE_RESUME_PROCESS = 0x00000010;

// IUnknown interface (base for all COM interfaces)
pub const IUnknownVTable = extern struct {
    QueryInterface: *const fn (*IUnknown, *const GUID, *?*anyopaque) callconv(windows.WINAPI) HRESULT,
    AddRef: *const fn (*IUnknown) callconv(windows.WINAPI) ULONG,
    Release: *const fn (*IUnknown) callconv(windows.WINAPI) ULONG,
};

pub const IUnknown = extern struct {
    vtbl: *const IUnknownVTable,

    const Self = @This();

    pub fn queryInterface(self: *Self, riid: *const GUID, object: *?*anyopaque) HRESULT {
        return self.vtbl.QueryInterface(self, riid, object);
    }

    pub fn addRef(self: *Self) ULONG {
        return self.vtbl.AddRef(self);
    }

    pub fn release(self: *Self) ULONG {
        return self.vtbl.Release(self);
    }
};

// IDebugClient5 interface
pub const IDebugClient5VTable = extern struct {
    // IUnknown methods
    QueryInterface: *const fn (*IDebugClient5, *const GUID, *?*anyopaque) callconv(windows.WINAPI) HRESULT,
    AddRef: *const fn (*IDebugClient5) callconv(windows.WINAPI) ULONG,
    Release: *const fn (*IDebugClient5) callconv(windows.WINAPI) ULONG,

    // IDebugClient methods
    AttachKernel: *const fn (*IDebugClient5, ULONG, ?[*:0]const u16) callconv(windows.WINAPI) HRESULT,
    GetKernelConnectionOptions: *const fn (*IDebugClient5, [*]u8, ULONG, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    SetKernelConnectionOptions: *const fn (*IDebugClient5, [*:0]const u8) callconv(windows.WINAPI) HRESULT,
    StartProcessServer: *const fn (*IDebugClient5, ULONG, ?[*:0]const u8, ?*anyopaque) callconv(windows.WINAPI) HRESULT,
    ConnectProcessServer: *const fn (*IDebugClient5, ?[*:0]const u8, ?**anyopaque) callconv(windows.WINAPI) HRESULT,
    DisconnectProcessServer: *const fn (*IDebugClient5, ?*anyopaque) callconv(windows.WINAPI) HRESULT,
    GetRunningProcessSystemIds: *const fn (*IDebugClient5, ?*anyopaque, ?*ULONG, ULONG, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    GetRunningProcessSystemIdByExecutableName: *const fn (*IDebugClient5, ?*anyopaque, [*:0]const u8, ULONG, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    GetRunningProcessDescription: *const fn (*IDebugClient5, ?*anyopaque, ULONG, ULONG, ?[*]u8, ULONG, ?*ULONG, ?[*]u8, ULONG, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    AttachProcess: *const fn (*IDebugClient5, ?*anyopaque, ULONG, ULONG) callconv(windows.WINAPI) HRESULT,
    CreateProcess: *const fn (*IDebugClient5, ?*anyopaque, [*:0]u8, ULONG) callconv(windows.WINAPI) HRESULT,
    CreateProcessAndAttach: *const fn (*IDebugClient5, ?*anyopaque, [*:0]u8, ULONG, ULONG, ULONG) callconv(windows.WINAPI) HRESULT,
    GetProcessOptions: *const fn (*IDebugClient5, *ULONG) callconv(windows.WINAPI) HRESULT,
    AddProcessOptions: *const fn (*IDebugClient5, ULONG) callconv(windows.WINAPI) HRESULT,
    RemoveProcessOptions: *const fn (*IDebugClient5, ULONG) callconv(windows.WINAPI) HRESULT,
    SetProcessOptions: *const fn (*IDebugClient5, ULONG) callconv(windows.WINAPI) HRESULT,
    OpenDumpFile: *const fn (*IDebugClient5, [*:0]const u8) callconv(windows.WINAPI) HRESULT,
    WriteDumpFile: *const fn (*IDebugClient5, [*:0]const u8, ULONG) callconv(windows.WINAPI) HRESULT,
    ConnectSession: *const fn (*IDebugClient5, ULONG, ULONG) callconv(windows.WINAPI) HRESULT,
    StartServer: *const fn (*IDebugClient5, [*:0]const u8) callconv(windows.WINAPI) HRESULT,
    OutputServer: *const fn (*IDebugClient5, ULONG, [*:0]const u8, ULONG) callconv(windows.WINAPI) HRESULT,
    TerminateProcesses: *const fn (*IDebugClient5) callconv(windows.WINAPI) HRESULT,
    DetachProcesses: *const fn (*IDebugClient5) callconv(windows.WINAPI) HRESULT,
    EndSession: *const fn (*IDebugClient5, ULONG) callconv(windows.WINAPI) HRESULT,
    GetExitCode: *const fn (*IDebugClient5, *ULONG) callconv(windows.WINAPI) HRESULT,
    DispatchCallbacks: *const fn (*IDebugClient5, ULONG) callconv(windows.WINAPI) HRESULT,
    ExitDispatch: *const fn (*IDebugClient5, *IDebugClient5) callconv(windows.WINAPI) HRESULT,
    CreateClient: *const fn (*IDebugClient5, **IDebugClient5) callconv(windows.WINAPI) HRESULT,
    GetInputCallbacks: *const fn (*IDebugClient5, **anyopaque) callconv(windows.WINAPI) HRESULT,
    SetInputCallbacks: *const fn (*IDebugClient5, ?*anyopaque) callconv(windows.WINAPI) HRESULT,
    GetOutputCallbacks: *const fn (*IDebugClient5, **anyopaque) callconv(windows.WINAPI) HRESULT,
    SetOutputCallbacks: *const fn (*IDebugClient5, ?*anyopaque) callconv(windows.WINAPI) HRESULT,
    GetOutputMask: *const fn (*IDebugClient5, *ULONG) callconv(windows.WINAPI) HRESULT,
    SetOutputMask: *const fn (*IDebugClient5, ULONG) callconv(windows.WINAPI) HRESULT,
    GetOtherOutputMask: *const fn (*IDebugClient5, *IDebugClient5, *ULONG) callconv(windows.WINAPI) HRESULT,
    SetOtherOutputMask: *const fn (*IDebugClient5, *IDebugClient5, ULONG) callconv(windows.WINAPI) HRESULT,
    GetOutputWidth: *const fn (*IDebugClient5, *ULONG) callconv(windows.WINAPI) HRESULT,
    SetOutputWidth: *const fn (*IDebugClient5, ULONG) callconv(windows.WINAPI) HRESULT,
    GetOutputLinePrefix: *const fn (*IDebugClient5, ?[*]u8, ULONG, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    SetOutputLinePrefix: *const fn (*IDebugClient5, ?[*:0]const u8) callconv(windows.WINAPI) HRESULT,
    GetIdentity: *const fn (*IDebugClient5, ?[*]u8, ULONG, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    OutputIdentity: *const fn (*IDebugClient5, ULONG, ULONG, [*:0]const u8) callconv(windows.WINAPI) HRESULT,
    GetEventCallbacks: *const fn (*IDebugClient5, **anyopaque) callconv(windows.WINAPI) HRESULT,
    SetEventCallbacks: *const fn (*IDebugClient5, ?*anyopaque) callconv(windows.WINAPI) HRESULT,
    FlushCallbacks: *const fn (*IDebugClient5) callconv(windows.WINAPI) HRESULT,

    // IDebugClient2 methods
    WriteDumpFile2: *const fn (*IDebugClient5, [*:0]const u8, ULONG, ULONG, ?[*:0]const u8) callconv(windows.WINAPI) HRESULT,
    AddDumpInformationFile: *const fn (*IDebugClient5, [*:0]const u8, ULONG) callconv(windows.WINAPI) HRESULT,
    EndProcessServer: *const fn (*IDebugClient5, ?*anyopaque) callconv(windows.WINAPI) HRESULT,
    WaitForProcessServerEnd: *const fn (*IDebugClient5, ULONG) callconv(windows.WINAPI) HRESULT,
    IsKernelDebuggerEnabled: *const fn (*IDebugClient5) callconv(windows.WINAPI) HRESULT,
    TerminateCurrentProcess: *const fn (*IDebugClient5) callconv(windows.WINAPI) HRESULT,
    DetachCurrentProcess: *const fn (*IDebugClient5) callconv(windows.WINAPI) HRESULT,
    AbandonCurrentProcess: *const fn (*IDebugClient5) callconv(windows.WINAPI) HRESULT,

    // IDebugClient3 methods
    GetRunningProcessSystemIdByExecutableNameWide: *const fn (*IDebugClient5, ?*anyopaque, [*:0]const u16, ULONG, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    GetRunningProcessDescriptionWide: *const fn (*IDebugClient5, ?*anyopaque, ULONG, ULONG, ?[*]u16, ULONG, ?*ULONG, ?[*]u16, ULONG, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    CreateProcessWide: *const fn (*IDebugClient5, ?*anyopaque, [*:0]u16, ULONG) callconv(windows.WINAPI) HRESULT,
    CreateProcessAndAttachWide: *const fn (*IDebugClient5, ?*anyopaque, [*:0]u16, ULONG, ULONG, ULONG) callconv(windows.WINAPI) HRESULT,

    // IDebugClient4 methods
    OpenDumpFileWide: *const fn (*IDebugClient5, [*:0]const u16, ULONG64) callconv(windows.WINAPI) HRESULT,
    WriteDumpFileWide: *const fn (*IDebugClient5, [*:0]const u16, ULONG64, ULONG, ULONG, ?[*:0]const u16) callconv(windows.WINAPI) HRESULT,
    AddDumpInformationFileWide: *const fn (*IDebugClient5, [*:0]const u16, ULONG64, ULONG) callconv(windows.WINAPI) HRESULT,
    GetNumberDumpFiles: *const fn (*IDebugClient5, *ULONG) callconv(windows.WINAPI) HRESULT,
    GetDumpFile: *const fn (*IDebugClient5, ULONG, ?[*]u8, ULONG, ?*ULONG, ?*ULONG64, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    GetDumpFileWide: *const fn (*IDebugClient5, ULONG, ?[*]u16, ULONG, ?*ULONG, ?*ULONG64, ?*ULONG) callconv(windows.WINAPI) HRESULT,

    // IDebugClient5 methods
    AttachKernelWide: *const fn (*IDebugClient5, ULONG, ?[*:0]const u16) callconv(windows.WINAPI) HRESULT,
    GetKernelConnectionOptionsWide: *const fn (*IDebugClient5, [*]u16, ULONG, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    SetKernelConnectionOptionsWide: *const fn (*IDebugClient5, [*:0]const u16) callconv(windows.WINAPI) HRESULT,
    StartProcessServerWide: *const fn (*IDebugClient5, ULONG, ?[*:0]const u16, ?*anyopaque) callconv(windows.WINAPI) HRESULT,
    ConnectProcessServerWide: *const fn (*IDebugClient5, ?[*:0]const u16, ?**anyopaque) callconv(windows.WINAPI) HRESULT,
    StartServerWide: *const fn (*IDebugClient5, [*:0]const u16) callconv(windows.WINAPI) HRESULT,
    OutputServerWide: *const fn (*IDebugClient5, ULONG, [*:0]const u16, ULONG) callconv(windows.WINAPI) HRESULT,
    GetOutputCallbacksWide: *const fn (*IDebugClient5, **anyopaque) callconv(windows.WINAPI) HRESULT,
    SetOutputCallbacksWide: *const fn (*IDebugClient5, ?*anyopaque) callconv(windows.WINAPI) HRESULT,
    GetOutputLinePrefixWide: *const fn (*IDebugClient5, ?[*]u16, ULONG, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    SetOutputLinePrefixWide: *const fn (*IDebugClient5, ?[*:0]const u16) callconv(windows.WINAPI) HRESULT,
    GetIdentityWide: *const fn (*IDebugClient5, ?[*]u16, ULONG, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    OutputIdentityWide: *const fn (*IDebugClient5, ULONG, ULONG, [*:0]const u16) callconv(windows.WINAPI) HRESULT,
    GetEventCallbacksWide: *const fn (*IDebugClient5, **anyopaque) callconv(windows.WINAPI) HRESULT,
    SetEventCallbacksWide: *const fn (*IDebugClient5, ?*anyopaque) callconv(windows.WINAPI) HRESULT,
    CreateProcess2: *const fn (*IDebugClient5, ?*anyopaque, [*:0]u8, ?*anyopaque, ULONG, ?[*:0]const u8, ?[*:0]const u8) callconv(windows.WINAPI) HRESULT,
    CreateProcess2Wide: *const fn (*IDebugClient5, ?*anyopaque, [*:0]u16, ?*anyopaque, ULONG, ?[*:0]const u16, ?[*:0]const u16) callconv(windows.WINAPI) HRESULT,
    CreateProcessAndAttach2: *const fn (*IDebugClient5, ?*anyopaque, [*:0]u8, ?*anyopaque, ULONG, ?[*:0]const u8, ?[*:0]const u8, ULONG, ULONG) callconv(windows.WINAPI) HRESULT,
    CreateProcessAndAttach2Wide: *const fn (*IDebugClient5, ?*anyopaque, [*:0]u16, ?*anyopaque, ULONG, ?[*:0]const u16, ?[*:0]const u16, ULONG, ULONG) callconv(windows.WINAPI) HRESULT,
    PushOutputLinePrefix: *const fn (*IDebugClient5, ?[*:0]const u8, ?**anyopaque) callconv(windows.WINAPI) HRESULT,
    PushOutputLinePrefixWide: *const fn (*IDebugClient5, ?[*:0]const u16, ?**anyopaque) callconv(windows.WINAPI) HRESULT,
    PopOutputLinePrefix: *const fn (*IDebugClient5, ?*anyopaque) callconv(windows.WINAPI) HRESULT,
    GetNumberInputCallbacks: *const fn (*IDebugClient5, *ULONG) callconv(windows.WINAPI) HRESULT,
    GetNumberOutputCallbacks: *const fn (*IDebugClient5, *ULONG) callconv(windows.WINAPI) HRESULT,
    GetNumberEventCallbacks: *const fn (*IDebugClient5, *ULONG) callconv(windows.WINAPI) HRESULT,
    GetQuitLockString: *const fn (*IDebugClient5, [*]u8, ULONG, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    SetQuitLockString: *const fn (*IDebugClient5, [*:0]const u8) callconv(windows.WINAPI) HRESULT,
    GetQuitLockStringWide: *const fn (*IDebugClient5, [*]u16, ULONG, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    SetQuitLockStringWide: *const fn (*IDebugClient5, [*:0]const u16) callconv(windows.WINAPI) HRESULT,
};

pub const IDebugClient5 = extern struct {
    vtbl: *const IDebugClient5VTable,

    const Self = @This();

    pub fn queryInterface(self: *Self, riid: *const GUID, object: *?*anyopaque) HRESULT {
        return self.vtbl.QueryInterface(self, riid, object);
    }

    pub fn addRef(self: *Self) ULONG {
        return self.vtbl.AddRef(self);
    }

    pub fn release(self: *Self) ULONG {
        return self.vtbl.Release(self);
    }

    pub fn createProcessWide(self: *Self, server: ?*anyopaque, command_line: [*:0]u16, flags: ULONG) HRESULT {
        return self.vtbl.CreateProcessWide(self, server, command_line, flags);
    }

    pub fn attachProcess(self: *Self, server: ?*anyopaque, process_id: ULONG, flags: ULONG) HRESULT {
        return self.vtbl.AttachProcess(self, server, process_id, flags);
    }

    pub fn setEventCallbacks(self: *Self, callbacks: ?*anyopaque) HRESULT {
        return self.vtbl.SetEventCallbacks(self, callbacks);
    }

    pub fn dispatchCallbacks(self: *Self, timeout: ULONG) HRESULT {
        return self.vtbl.DispatchCallbacks(self, timeout);
    }

    pub fn detachProcesses(self: *Self) HRESULT {
        return self.vtbl.DetachProcesses(self);
    }

    pub fn terminateProcesses(self: *Self) HRESULT {
        return self.vtbl.TerminateProcesses(self);
    }
};

// IDebugControl4 interface (simplified for essential methods)
pub const IDebugControl4VTable = extern struct {
    // IUnknown methods
    QueryInterface: *const fn (*IDebugControl4, *const GUID, *?*anyopaque) callconv(windows.WINAPI) HRESULT,
    AddRef: *const fn (*IDebugControl4) callconv(windows.WINAPI) ULONG,
    Release: *const fn (*IDebugControl4) callconv(windows.WINAPI) ULONG,

    // Essential IDebugControl methods (abbreviated list)
    GetInterrupt: *const fn (*IDebugControl4) callconv(windows.WINAPI) HRESULT,
    SetInterrupt: *const fn (*IDebugControl4, ULONG) callconv(windows.WINAPI) HRESULT,
    GetInterruptTimeout: *const fn (*IDebugControl4, *ULONG) callconv(windows.WINAPI) HRESULT,
    SetInterruptTimeout: *const fn (*IDebugControl4, ULONG) callconv(windows.WINAPI) HRESULT,
    GetLogFile: *const fn (*IDebugControl4, [*]u8, ULONG, ?*ULONG, *windows.BOOL) callconv(windows.WINAPI) HRESULT,
    OpenLogFile: *const fn (*IDebugControl4, [*:0]const u8, windows.BOOL) callconv(windows.WINAPI) HRESULT,
    CloseLogFile: *const fn (*IDebugControl4) callconv(windows.WINAPI) HRESULT,
    GetLogMask: *const fn (*IDebugControl4, *ULONG) callconv(windows.WINAPI) HRESULT,
    SetLogMask: *const fn (*IDebugControl4, ULONG) callconv(windows.WINAPI) HRESULT,
    Input: *const fn (*IDebugControl4, [*]u8, ULONG, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    ReturnInput: *const fn (*IDebugControl4, [*:0]const u8) callconv(windows.WINAPI) HRESULT,
    Output: *const fn (*IDebugControl4, ULONG, [*:0]const u8) callconv(windows.WINAPI) HRESULT,
    OutputVaList: *const fn (*IDebugControl4, ULONG, [*:0]const u8, *anyopaque) callconv(windows.WINAPI) HRESULT,
    ControlledOutput: *const fn (*IDebugControl4, ULONG, ULONG, [*:0]const u8) callconv(windows.WINAPI) HRESULT,
    ControlledOutputVaList: *const fn (*IDebugControl4, ULONG, ULONG, [*:0]const u8, *anyopaque) callconv(windows.WINAPI) HRESULT,
    OutputPrompt: *const fn (*IDebugControl4, ULONG, [*:0]const u8) callconv(windows.WINAPI) HRESULT,
    OutputPromptVaList: *const fn (*IDebugControl4, ULONG, [*:0]const u8, *anyopaque) callconv(windows.WINAPI) HRESULT,
    GetPromptText: *const fn (*IDebugControl4, [*]u8, ULONG, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    OutputCurrentState: *const fn (*IDebugControl4, ULONG, ULONG) callconv(windows.WINAPI) HRESULT,
    OutputVersionInformation: *const fn (*IDebugControl4, ULONG) callconv(windows.WINAPI) HRESULT,
    GetNotifyEventHandle: *const fn (*IDebugControl4, *windows.HANDLE) callconv(windows.WINAPI) HRESULT,
    SetNotifyEventHandle: *const fn (*IDebugControl4, windows.HANDLE) callconv(windows.WINAPI) HRESULT,
    Assemble: *const fn (*IDebugControl4, ULONG64, [*:0]const u8, *ULONG64) callconv(windows.WINAPI) HRESULT,
    Disassemble: *const fn (*IDebugControl4, ULONG64, ULONG, [*]u8, ULONG, ?*ULONG, *ULONG64) callconv(windows.WINAPI) HRESULT,
    GetDisassembleEffectiveOffset: *const fn (*IDebugControl4, *ULONG64) callconv(windows.WINAPI) HRESULT,
    OutputDisassembly: *const fn (*IDebugControl4, ULONG, ULONG64, ULONG, *ULONG64) callconv(windows.WINAPI) HRESULT,
    OutputDisassemblyLines: *const fn (*IDebugControl4, ULONG, ULONG, ULONG, ULONG64, ULONG, ?*ULONG, *ULONG64, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    GetNearInstruction: *const fn (*IDebugControl4, ULONG64, i32, *ULONG64) callconv(windows.WINAPI) HRESULT,
    GetStackTrace: *const fn (*IDebugControl4, ULONG64, ULONG64, ULONG64, ?*anyopaque, ULONG, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    GetReturnOffset: *const fn (*IDebugControl4, *ULONG64) callconv(windows.WINAPI) HRESULT,
    OutputStackTrace: *const fn (*IDebugControl4, ULONG, ?*const anyopaque, ULONG, ULONG) callconv(windows.WINAPI) HRESULT,
    GetDebuggeeType: *const fn (*IDebugControl4, *ULONG, *ULONG) callconv(windows.WINAPI) HRESULT,
    GetActualProcessorType: *const fn (*IDebugControl4, *ULONG) callconv(windows.WINAPI) HRESULT,
    GetExecutingProcessorType: *const fn (*IDebugControl4, *ULONG) callconv(windows.WINAPI) HRESULT,
    GetNumberPossibleExecutingProcessorTypes: *const fn (*IDebugControl4, *ULONG) callconv(windows.WINAPI) HRESULT,
    GetPossibleExecutingProcessorTypes: *const fn (*IDebugControl4, ULONG, ?*ULONG, ULONG, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    GetNumberProcessors: *const fn (*IDebugControl4, *ULONG) callconv(windows.WINAPI) HRESULT,
    GetSystemVersion: *const fn (*IDebugControl4, *ULONG, *ULONG, *ULONG, *ULONG, *ULONG, *ULONG, *ULONG, [*]u8, ULONG, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    GetPageSize: *const fn (*IDebugControl4, *ULONG) callconv(windows.WINAPI) HRESULT,
    IsPointer64Bit: *const fn (*IDebugControl4) callconv(windows.WINAPI) HRESULT,
    ReadBugCheckData: *const fn (*IDebugControl4, *ULONG, *ULONG64, *ULONG64, *ULONG64, *ULONG64, *ULONG64) callconv(windows.WINAPI) HRESULT,
    GetNumberSupportedProcessorTypes: *const fn (*IDebugControl4, *ULONG) callconv(windows.WINAPI) HRESULT,
    GetSupportedProcessorTypes: *const fn (*IDebugControl4, ULONG, ?*ULONG, ULONG, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    GetProcessorTypeNames: *const fn (*IDebugControl4, ULONG, [*]u8, ULONG, ?*ULONG, [*]u8, ULONG, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    GetEffectiveProcessorType: *const fn (*IDebugControl4, *ULONG) callconv(windows.WINAPI) HRESULT,
    SetEffectiveProcessorType: *const fn (*IDebugControl4, ULONG) callconv(windows.WINAPI) HRESULT,
    GetExecutionStatus: *const fn (*IDebugControl4, *ULONG) callconv(windows.WINAPI) HRESULT,
    SetExecutionStatus: *const fn (*IDebugControl4, ULONG) callconv(windows.WINAPI) HRESULT,
    GetCodeLevel: *const fn (*IDebugControl4, *ULONG) callconv(windows.WINAPI) HRESULT,
    SetCodeLevel: *const fn (*IDebugControl4, ULONG) callconv(windows.WINAPI) HRESULT,
    GetEngineOptions: *const fn (*IDebugControl4, *ULONG) callconv(windows.WINAPI) HRESULT,
    AddEngineOptions: *const fn (*IDebugControl4, ULONG) callconv(windows.WINAPI) HRESULT,
    RemoveEngineOptions: *const fn (*IDebugControl4, ULONG) callconv(windows.WINAPI) HRESULT,
    SetEngineOptions: *const fn (*IDebugControl4, ULONG) callconv(windows.WINAPI) HRESULT,
    GetSystemErrorControl: *const fn (*IDebugControl4, *ULONG, *ULONG) callconv(windows.WINAPI) HRESULT,
    SetSystemErrorControl: *const fn (*IDebugControl4, ULONG, ULONG) callconv(windows.WINAPI) HRESULT,
    GetTextMacro: *const fn (*IDebugControl4, ULONG, [*]u8, ULONG, ?*ULONG, [*]u8, ULONG, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    SetTextMacro: *const fn (*IDebugControl4, ULONG, [*:0]const u8, [*:0]const u8) callconv(windows.WINAPI) HRESULT,
    GetRadix: *const fn (*IDebugControl4, *ULONG) callconv(windows.WINAPI) HRESULT,
    SetRadix: *const fn (*IDebugControl4, ULONG) callconv(windows.WINAPI) HRESULT,
    Evaluate: *const fn (*IDebugControl4, [*:0]const u8, ULONG, *anyopaque, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    CoerceValue: *const fn (*IDebugControl4, *anyopaque, ULONG, *anyopaque) callconv(windows.WINAPI) HRESULT,
    CoerceValues: *const fn (*IDebugControl4, ULONG, ?*anyopaque, ?*ULONG, ?*anyopaque) callconv(windows.WINAPI) HRESULT,
    Execute: *const fn (*IDebugControl4, ULONG, [*:0]const u8, ULONG) callconv(windows.WINAPI) HRESULT,
    ExecuteCommandFile: *const fn (*IDebugControl4, ULONG, [*:0]const u8, ULONG) callconv(windows.WINAPI) HRESULT,
    GetNumberBreakpoints: *const fn (*IDebugControl4, *ULONG) callconv(windows.WINAPI) HRESULT,
    GetBreakpointByIndex: *const fn (*IDebugControl4, ULONG, **anyopaque) callconv(windows.WINAPI) HRESULT,
    GetBreakpointById: *const fn (*IDebugControl4, ULONG, **anyopaque) callconv(windows.WINAPI) HRESULT,
    GetBreakpointParameters: *const fn (*IDebugControl4, ULONG, ?*ULONG, ULONG, ?*anyopaque) callconv(windows.WINAPI) HRESULT,
    AddBreakpoint: *const fn (*IDebugControl4, ULONG, ULONG, **anyopaque) callconv(windows.WINAPI) HRESULT,
    RemoveBreakpoint: *const fn (*IDebugControl4, *anyopaque) callconv(windows.WINAPI) HRESULT,
    AddExtension: *const fn (*IDebugControl4, [*:0]const u8, ULONG, *windows.HANDLE) callconv(windows.WINAPI) HRESULT,
    RemoveExtension: *const fn (*IDebugControl4, windows.HANDLE) callconv(windows.WINAPI) HRESULT,
    GetExtensionByPath: *const fn (*IDebugControl4, [*:0]const u8, *windows.HANDLE) callconv(windows.WINAPI) HRESULT,
    CallExtension: *const fn (*IDebugControl4, windows.HANDLE, [*:0]const u8, [*:0]const u8) callconv(windows.WINAPI) HRESULT,
    GetExtensionFunction: *const fn (*IDebugControl4, windows.HANDLE, [*:0]const u8, *?*const fn () callconv(.C) void) callconv(windows.WINAPI) HRESULT,
    GetWindbgExtensionApis32: *const fn (*IDebugControl4, *anyopaque) callconv(windows.WINAPI) HRESULT,
    GetWindbgExtensionApis64: *const fn (*IDebugControl4, *anyopaque) callconv(windows.WINAPI) HRESULT,
    GetNumberEventFilters: *const fn (*IDebugControl4, *ULONG, *ULONG, *ULONG) callconv(windows.WINAPI) HRESULT,
    GetEventFilterText: *const fn (*IDebugControl4, ULONG, [*]u8, ULONG, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    GetEventFilterCommand: *const fn (*IDebugControl4, ULONG, [*]u8, ULONG, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    SetEventFilterCommand: *const fn (*IDebugControl4, ULONG, [*:0]const u8) callconv(windows.WINAPI) HRESULT,
    GetSpecificFilterParameters: *const fn (*IDebugControl4, ULONG, ?*ULONG, ULONG, ?*anyopaque) callconv(windows.WINAPI) HRESULT,
    SetSpecificFilterParameters: *const fn (*IDebugControl4, ULONG, ?*ULONG, ULONG, ?*anyopaque) callconv(windows.WINAPI) HRESULT,
    GetSpecificFilterArgument: *const fn (*IDebugControl4, ULONG, [*]u8, ULONG, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    SetSpecificFilterArgument: *const fn (*IDebugControl4, ULONG, [*:0]const u8) callconv(windows.WINAPI) HRESULT,
    GetExceptionFilterParameters: *const fn (*IDebugControl4, ULONG, ?*ULONG, ULONG, ?*anyopaque) callconv(windows.WINAPI) HRESULT,
    SetExceptionFilterParameters: *const fn (*IDebugControl4, ULONG, ?*anyopaque) callconv(windows.WINAPI) HRESULT,
    GetExceptionFilterSecondCommand: *const fn (*IDebugControl4, ULONG, [*]u8, ULONG, ?*ULONG) callconv(windows.WINAPI) HRESULT,
    SetExceptionFilterSecondCommand: *const fn (*IDebugControl4, ULONG, [*:0]const u8) callconv(windows.WINAPI) HRESULT,
    WaitForEvent: *const fn (*IDebugControl4, ULONG, ULONG) callconv(windows.WINAPI) HRESULT,
    GetLastEventInformation: *const fn (*IDebugControl4, *ULONG, *ULONG, *ULONG, ?*anyopaque, ULONG, ?*ULONG, ?[*]u8, ULONG, ?*ULONG) callconv(windows.WINAPI) HRESULT,

    // Placeholder for remaining methods - add as needed
    // ... (many more methods in full interface)
};

pub const IDebugControl4 = extern struct {
    vtbl: *const IDebugControl4VTable,

    const Self = @This();

    pub fn queryInterface(self: *Self, riid: *const GUID, object: *?*anyopaque) HRESULT {
        return self.vtbl.QueryInterface(self, riid, object);
    }

    pub fn addRef(self: *Self) ULONG {
        return self.vtbl.AddRef(self);
    }

    pub fn release(self: *Self) ULONG {
        return self.vtbl.Release(self);
    }

    pub fn setExecutionStatus(self: *Self, status: ULONG) HRESULT {
        return self.vtbl.SetExecutionStatus(self, status);
    }

    pub fn getExecutionStatus(self: *Self, status: *ULONG) HRESULT {
        return self.vtbl.GetExecutionStatus(self, status);
    }

    pub fn waitForEvent(self: *Self, flags: ULONG, timeout: ULONG) HRESULT {
        return self.vtbl.WaitForEvent(self, flags, timeout);
    }

    pub fn output(self: *Self, mask: ULONG, text: [*:0]const u8) HRESULT {
        return self.vtbl.Output(self, mask, text);
    }

    pub fn addBreakpoint(self: *Self, type_: ULONG, desired_id: ULONG, bp: **anyopaque) HRESULT {
        return self.vtbl.AddBreakpoint(self, type_, desired_id, bp);
    }
};

// IDebugEventCallbacks interface
pub const IDebugEventCallbacksVTable = extern struct {
    // IUnknown methods
    QueryInterface: *const fn (*IDebugEventCallbacks, *const GUID, *?*anyopaque) callconv(windows.WINAPI) HRESULT,
    AddRef: *const fn (*IDebugEventCallbacks) callconv(windows.WINAPI) ULONG,
    Release: *const fn (*IDebugEventCallbacks) callconv(windows.WINAPI) ULONG,

    // IDebugEventCallbacks methods
    GetInterestMask: *const fn (*IDebugEventCallbacks, *ULONG) callconv(windows.WINAPI) HRESULT,
    Breakpoint: *const fn (*IDebugEventCallbacks, *anyopaque) callconv(windows.WINAPI) ULONG,
    Exception: *const fn (*IDebugEventCallbacks, *anyopaque, windows.BOOL) callconv(windows.WINAPI) ULONG,
    CreateThread: *const fn (*IDebugEventCallbacks, windows.HANDLE, *anyopaque, *anyopaque) callconv(windows.WINAPI) ULONG,
    ExitThread: *const fn (*IDebugEventCallbacks, ULONG) callconv(windows.WINAPI) ULONG,
    CreateProcess: *const fn (*IDebugEventCallbacks, windows.HANDLE, windows.HANDLE, *anyopaque, *anyopaque, *anyopaque, *anyopaque, windows.HANDLE, windows.HANDLE, *anyopaque, [*:0]const u16) callconv(windows.WINAPI) ULONG,
    ExitProcess: *const fn (*IDebugEventCallbacks, ULONG) callconv(windows.WINAPI) ULONG,
    LoadModule: *const fn (*IDebugEventCallbacks, windows.HANDLE, ULONG64, [*:0]const u16, [*:0]const u16, ULONG, ULONG) callconv(windows.WINAPI) ULONG,
    UnloadModule: *const fn (*IDebugEventCallbacks, [*:0]const u16, ULONG64) callconv(windows.WINAPI) ULONG,
    SystemError: *const fn (*IDebugEventCallbacks, ULONG, ULONG) callconv(windows.WINAPI) ULONG,
    SessionStatus: *const fn (*IDebugEventCallbacks, ULONG) callconv(windows.WINAPI) ULONG,
    ChangeDebuggeeState: *const fn (*IDebugEventCallbacks, ULONG, ULONG64) callconv(windows.WINAPI) ULONG,
    ChangeEngineState: *const fn (*IDebugEventCallbacks, ULONG, ULONG64) callconv(windows.WINAPI) ULONG,
    ChangeSymbolState: *const fn (*IDebugEventCallbacks, ULONG, ULONG64) callconv(windows.WINAPI) ULONG,
};

pub const IDebugEventCallbacks = extern struct {
    vtbl: *const IDebugEventCallbacksVTable,

    const Self = @This();

    pub fn queryInterface(self: *Self, riid: *const GUID, object: *?*anyopaque) HRESULT {
        return self.vtbl.QueryInterface(self, riid, object);
    }

    pub fn addRef(self: *Self) ULONG {
        return self.vtbl.AddRef(self);
    }

    pub fn release(self: *Self) ULONG {
        return self.vtbl.Release(self);
    }
};

// Common GUIDs for interface queries
pub const IID_IDebugClient5 = GUID{
    .Data1 = 0xe3acb9d7,
    .Data2 = 0x7ec2,
    .Data3 = 0x4f0c,
    .Data4 = .{ 0xa0, 0xda, 0xe8, 0x1e, 0x0c, 0xbb, 0xe6, 0x28 },
};

pub const IID_IDebugControl4 = GUID{
    .Data1 = 0x94e60ce9,
    .Data2 = 0x9b41,
    .Data3 = 0x4b19,
    .Data4 = .{ 0x9f, 0xc0, 0x6d, 0x9e, 0xb3, 0x52, 0x72, 0xb3 },
};

pub const IID_IDebugSymbols3 = GUID{
    .Data1 = 0xf02fbecc,
    .Data2 = 0x50ac,
    .Data3 = 0x4f36,
    .Data4 = .{ 0x9a, 0xd9, 0xc9, 0x75, 0xe8, 0xf3, 0x2f, 0xf8 },
};

pub const IID_IDebugRegisters2 = GUID{
    .Data1 = 0x1656afa9,
    .Data2 = 0x19c6,
    .Data3 = 0x4e3a,
    .Data4 = .{ 0x97, 0xe7, 0x5d, 0xc9, 0x16, 0x0c, 0xf9, 0xc4 },
};

pub const IID_IDebugDataSpaces4 = GUID{
    .Data1 = 0xd98ada1f,
    .Data2 = 0x29e9,
    .Data3 = 0x4ef5,
    .Data4 = .{ 0xa6, 0xc0, 0xe5, 0x3e, 0x34, 0x88, 0x34, 0x2e },
};

pub const IID_IDebugSystemObjects4 = GUID{
    .Data1 = 0x489468e6,
    .Data2 = 0x7d0f,
    .Data3 = 0x4af5,
    .Data4 = .{ 0x87, 0xab, 0x25, 0x20, 0x7a, 0x4e, 0x4c, 0x61 },
};

// DbgEng engine creation function
pub extern "dbgeng" fn DebugCreate(interface_id: *const GUID, interface: *?*anyopaque) callconv(windows.WINAPI) HRESULT;
