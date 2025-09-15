const std = @import("std");
const windows = std.os.windows;
const WINAPI = windows.WINAPI;

// Windows API types
const HANDLE = windows.HANDLE;
const DWORD = windows.DWORD;
const BOOL = windows.BOOL;

// Windows API functions
extern "kernel32" fn CloseHandle(hObject: HANDLE) callconv(WINAPI) BOOL;

// Not sure why these are missing from standard Zig Windows bindings, but the definitions are in winnt.h
pub const CONTEXT_AMD64: DWORD = 0x00100000;
pub const CONTEXT_CONTROL: DWORD = CONTEXT_AMD64 | 0x00000001;
pub const CONTEXT_INTEGER: DWORD = CONTEXT_AMD64 | 0x00000002;
pub const CONTEXT_SEGMENTS: DWORD = CONTEXT_AMD64 | 0x00000004;
pub const CONTEXT_FLOATING_POINT: DWORD = CONTEXT_AMD64 | 0x00000008;
pub const CONTEXT_DEBUG_REGISTERS: DWORD = CONTEXT_AMD64 | 0x00000010;
pub const CONTEXT_FULL: DWORD = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT;
pub const CONTEXT_ALL: DWORD = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS;

// Use Zig's built-in Windows CONTEXT structure
pub const CONTEXT = windows.CONTEXT;

// 16-byte aligned context structure (required by Windows API)
pub const AlignedContext = struct {
    context: CONTEXT align(16),
};

// RAII wrapper for Windows handles - automatically closes handle on destruction
pub const AutoClosedHandle = struct {
    handle: HANDLE,

    pub fn init(handle: HANDLE) AutoClosedHandle {
        return AutoClosedHandle{ .handle = handle };
    }

    pub fn deinit(self: *AutoClosedHandle) void {
        _ = CloseHandle(self.handle);
    }

    pub fn get(self: AutoClosedHandle) HANDLE {
        return self.handle;
    }
};
