//! IDebugEventCallbacks implementation for handling debug events
//! This module provides a concrete implementation of the IDebugEventCallbacks interface
//! to handle various debugging events like process creation, module loading, exceptions, etc.

const std = @import("std");
const windows = std.os.windows;
const com_interfaces = @import("com_interfaces.zig");

const HRESULT = com_interfaces.HRESULT;
const ULONG = com_interfaces.ULONG;
const ULONG64 = com_interfaces.ULONG64;
const IDebugEventCallbacks = com_interfaces.IDebugEventCallbacks;
const IDebugEventCallbacksVTable = com_interfaces.IDebugEventCallbacksVTable;

// Debug interest mask flags
pub const DEBUG_EVENT_BREAKPOINT = 0x00000001;
pub const DEBUG_EVENT_EXCEPTION = 0x00000002;
pub const DEBUG_EVENT_CREATE_THREAD = 0x00000004;
pub const DEBUG_EVENT_EXIT_THREAD = 0x00000008;
pub const DEBUG_EVENT_CREATE_PROCESS = 0x00000010;
pub const DEBUG_EVENT_EXIT_PROCESS = 0x00000020;
pub const DEBUG_EVENT_LOAD_MODULE = 0x00000040;
pub const DEBUG_EVENT_UNLOAD_MODULE = 0x00000080;
pub const DEBUG_EVENT_SYSTEM_ERROR = 0x00000100;
pub const DEBUG_EVENT_SESSION_STATUS = 0x00000200;
pub const DEBUG_EVENT_CHANGE_DEBUGGEE_STATE = 0x00000400;
pub const DEBUG_EVENT_CHANGE_ENGINE_STATE = 0x00000800;
pub const DEBUG_EVENT_CHANGE_SYMBOL_STATE = 0x00001000;

// DebugEventCallbacks implementation
pub const DebugEventCallbacks = struct {
    vtbl: *const IDebugEventCallbacksVTable,
    ref_count: ULONG,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn create(allocator: std.mem.Allocator) !*Self {
        const self = try allocator.create(Self);
        self.* = Self{
            .vtbl = &vtable,
            .ref_count = 1,
            .allocator = allocator,
        };
        return self;
    }

    pub fn destroy(self: *Self) void {
        self.allocator.destroy(self);
    }

    // COM IUnknown implementation
    fn queryInterface(self: *IDebugEventCallbacks, riid: *const windows.GUID, object: *?*anyopaque) callconv(windows.WINAPI) HRESULT {
        _ = self;
        _ = riid;
        _ = object;
        return windows.E_NOINTERFACE;
    }

    fn addRef(self: *IDebugEventCallbacks) callconv(windows.WINAPI) ULONG {
        const self_typed = @as(*Self, @ptrCast(@alignCast(self)));
        self_typed.ref_count += 1;
        return self_typed.ref_count;
    }

    fn release(self: *IDebugEventCallbacks) callconv(windows.WINAPI) ULONG {
        const self_typed = @as(*Self, @ptrCast(@alignCast(self)));
        self_typed.ref_count -= 1;
        const new_count = self_typed.ref_count;

        if (new_count == 0) {
            self_typed.destroy();
        }

        return new_count;
    }

    // IDebugEventCallbacks implementation
    fn getInterestMask(self: *IDebugEventCallbacks, mask: *ULONG) callconv(windows.WINAPI) HRESULT {
        _ = self;
        // We want to receive all event types
        mask.* = DEBUG_EVENT_BREAKPOINT |
            DEBUG_EVENT_EXCEPTION |
            DEBUG_EVENT_CREATE_THREAD |
            DEBUG_EVENT_EXIT_THREAD |
            DEBUG_EVENT_CREATE_PROCESS |
            DEBUG_EVENT_EXIT_PROCESS |
            DEBUG_EVENT_LOAD_MODULE |
            DEBUG_EVENT_UNLOAD_MODULE |
            DEBUG_EVENT_SYSTEM_ERROR |
            DEBUG_EVENT_SESSION_STATUS |
            DEBUG_EVENT_CHANGE_DEBUGGEE_STATE |
            DEBUG_EVENT_CHANGE_ENGINE_STATE |
            DEBUG_EVENT_CHANGE_SYMBOL_STATE;
        return windows.S_OK;
    }

    fn breakpoint(self: *IDebugEventCallbacks, bp: *anyopaque) callconv(windows.WINAPI) ULONG {
        _ = self;
        _ = bp;
        std.debug.print("[DebugEvent] Breakpoint hit\n", .{});
        return com_interfaces.DEBUG_STATUS_BREAK;
    }

    fn exception(self: *IDebugEventCallbacks, exception_info: *anyopaque, first_chance: windows.BOOL) callconv(windows.WINAPI) ULONG {
        _ = self;
        _ = exception_info;
        if (first_chance != 0) {
            std.debug.print("[DebugEvent] First chance exception\n", .{});
            return com_interfaces.DEBUG_STATUS_GO_NOT_HANDLED;
        } else {
            std.debug.print("[DebugEvent] Second chance exception\n", .{});
            return com_interfaces.DEBUG_STATUS_BREAK;
        }
    }

    fn createThread(self: *IDebugEventCallbacks, handle: windows.HANDLE, data_offset: *anyopaque, start_offset: *anyopaque) callconv(windows.WINAPI) ULONG {
        _ = self;
        _ = handle;
        _ = data_offset;
        _ = start_offset;
        std.debug.print("[DebugEvent] Thread created\n", .{});
        return com_interfaces.DEBUG_STATUS_NO_CHANGE;
    }

    fn exitThread(self: *IDebugEventCallbacks, exit_code: ULONG) callconv(windows.WINAPI) ULONG {
        _ = self;
        std.debug.print("[DebugEvent] Thread exited with code: {}\n", .{exit_code});
        return com_interfaces.DEBUG_STATUS_NO_CHANGE;
    }

    fn createProcess(
        self: *IDebugEventCallbacks,
        image_file_handle: windows.HANDLE,
        handle: windows.HANDLE,
        base_offset: *anyopaque,
        module_size: *anyopaque,
        module_name: *anyopaque,
        image_name: *anyopaque,
        initial_thread_handle: windows.HANDLE,
        thread_data_offset: *anyopaque,
        start_offset: *anyopaque,
        executable_name: [*:0]const u16,
    ) callconv(windows.WINAPI) ULONG {
        _ = self;
        _ = image_file_handle;
        _ = handle;
        _ = base_offset;
        _ = module_size;
        _ = module_name;
        _ = image_name;
        _ = initial_thread_handle;
        _ = thread_data_offset;
        _ = start_offset;

        // Convert wide string to UTF-8 for printing
        var utf8_buf: [256]u8 = undefined;
        const utf8_len = std.unicode.utf16LeToUtf8(utf8_buf[0..], std.mem.span(executable_name)) catch {
            std.debug.print("[DebugEvent] Process created: <invalid name>\n", .{});
            return com_interfaces.DEBUG_STATUS_GO;
        };
        std.debug.print("[DebugEvent] Process created: {s}\n", .{utf8_buf[0..utf8_len]});
        return com_interfaces.DEBUG_STATUS_GO;
    }

    fn exitProcess(self: *IDebugEventCallbacks, exit_code: ULONG) callconv(windows.WINAPI) ULONG {
        _ = self;
        std.debug.print("[DebugEvent] Process exited with code: {}\n", .{exit_code});
        return com_interfaces.DEBUG_STATUS_NO_CHANGE;
    }

    fn loadModule(
        self: *IDebugEventCallbacks,
        image_file_handle: windows.HANDLE,
        base_offset: ULONG64,
        module_name: [*:0]const u16,
        image_name: [*:0]const u16,
        checksum: ULONG,
        time_stamp: ULONG,
    ) callconv(windows.WINAPI) ULONG {
        _ = self;
        _ = image_file_handle;
        _ = checksum;
        _ = time_stamp;

        // Convert wide strings to UTF-8 for printing
        var module_name_buf: [256]u8 = undefined;
        var image_name_buf: [256]u8 = undefined;

        const module_name_utf8 = blk: {
            const len = std.unicode.utf16LeToUtf8(module_name_buf[0..], std.mem.span(module_name)) catch break :blk "<invalid>";
            break :blk module_name_buf[0..len];
        };

        const image_name_utf8 = blk: {
            const len = std.unicode.utf16LeToUtf8(image_name_buf[0..], std.mem.span(image_name)) catch break :blk "<invalid>";
            break :blk image_name_buf[0..len];
        };

        std.debug.print("[DebugEvent] Module loaded: {s} (Image: {s}, Base: 0x{X})\n", .{ module_name_utf8, image_name_utf8, base_offset });
        return com_interfaces.DEBUG_STATUS_NO_CHANGE;
    }

    fn unloadModule(self: *IDebugEventCallbacks, image_name: [*:0]const u16, base_offset: ULONG64) callconv(windows.WINAPI) ULONG {
        _ = self;

        // Convert wide string to UTF-8 for printing
        var image_name_buf: [256]u8 = undefined;
        const image_name_utf8 = blk: {
            const len = std.unicode.utf16LeToUtf8(image_name_buf[0..], std.mem.span(image_name)) catch break :blk "<invalid>";
            break :blk image_name_buf[0..len];
        };

        std.debug.print("[DebugEvent] Module unloaded: {s} (Base: 0x{X})\n", .{ image_name_utf8, base_offset });
        return com_interfaces.DEBUG_STATUS_NO_CHANGE;
    }

    fn systemError(self: *IDebugEventCallbacks, error_code: ULONG, level: ULONG) callconv(windows.WINAPI) ULONG {
        _ = self;
        std.debug.print("[DebugEvent] System error: code={}, level={}\n", .{ error_code, level });
        return com_interfaces.DEBUG_STATUS_NO_CHANGE;
    }

    fn sessionStatus(self: *IDebugEventCallbacks, status: ULONG) callconv(windows.WINAPI) ULONG {
        _ = self;
        const status_str = switch (status) {
            0 => "ACTIVE",
            1 => "END_SESSION_ACTIVE_TERMINATE",
            2 => "END_SESSION_ACTIVE_DETACH",
            3 => "END_SESSION_PASSIVE",
            4 => "REBOOT",
            5 => "HIBERNATE",
            6 => "FAILURE",
            else => "UNKNOWN",
        };
        std.debug.print("[DebugEvent] Session status changed: {} ({s})\n", .{ status, status_str });
        return com_interfaces.DEBUG_STATUS_NO_CHANGE;
    }

    fn changeDebuggeeState(self: *IDebugEventCallbacks, flags: ULONG, argument: ULONG64) callconv(windows.WINAPI) ULONG {
        _ = self;
        std.debug.print("[DebugEvent] Debuggee state changed: flags=0x{X}, arg=0x{X}\n", .{ flags, argument });
        return com_interfaces.DEBUG_STATUS_NO_CHANGE;
    }

    fn changeEngineState(self: *IDebugEventCallbacks, flags: ULONG, argument: ULONG64) callconv(windows.WINAPI) ULONG {
        _ = self;
        std.debug.print("[DebugEvent] Engine state changed: flags=0x{X}, arg=0x{X}\n", .{ flags, argument });
        return com_interfaces.DEBUG_STATUS_NO_CHANGE;
    }

    fn changeSymbolState(self: *IDebugEventCallbacks, flags: ULONG, argument: ULONG64) callconv(windows.WINAPI) ULONG {
        _ = self;
        std.debug.print("[DebugEvent] Symbol state changed: flags=0x{X}, arg=0x{X}\n", .{ flags, argument });
        return com_interfaces.DEBUG_STATUS_NO_CHANGE;
    }

    // VTable for the interface
    const vtable = IDebugEventCallbacksVTable{
        .QueryInterface = queryInterface,
        .AddRef = addRef,
        .Release = release,
        .GetInterestMask = getInterestMask,
        .Breakpoint = breakpoint,
        .Exception = exception,
        .CreateThread = createThread,
        .ExitThread = exitThread,
        .CreateProcess = createProcess,
        .ExitProcess = exitProcess,
        .LoadModule = loadModule,
        .UnloadModule = unloadModule,
        .SystemError = systemError,
        .SessionStatus = sessionStatus,
        .ChangeDebuggeeState = changeDebuggeeState,
        .ChangeEngineState = changeEngineState,
        .ChangeSymbolState = changeSymbolState,
    };
};
