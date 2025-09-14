const std = @import("std");
const windows = std.os.windows;
const WINAPI = windows.WINAPI;
const print = std.debug.print;

const memory = @import("memory.zig");

// Windows API types
const HANDLE = windows.HANDLE;
const DWORD = windows.DWORD;
const BOOL = windows.BOOL;
const WORD = u16;
const LPVOID = ?*anyopaque;

// Windows API functions
extern "kernel32" fn WaitForDebugEventEx(lpDebugEvent: *DEBUG_EVENT, dwMilliseconds: DWORD) callconv(WINAPI) BOOL;
extern "kernel32" fn GetThreadId(Thread: HANDLE) callconv(WINAPI) DWORD;
extern "kernel32" fn CloseHandle(hObject: HANDLE) callconv(WINAPI) BOOL;
extern "kernel32" fn GetFinalPathNameByHandleW(
    hFile: HANDLE,
    lpszFilePath: [*]u16,
    cchFilePath: DWORD,
    dwFlags: DWORD,
) callconv(WINAPI) DWORD;

// Debug event constants  
const EXCEPTION_DEBUG_EVENT: DWORD = 1;
const CREATE_THREAD_DEBUG_EVENT: DWORD = 2;
const CREATE_PROCESS_DEBUG_EVENT: DWORD = 3;
const EXIT_THREAD_DEBUG_EVENT: DWORD = 4;
const EXIT_PROCESS_DEBUG_EVENT: DWORD = 5;
const LOAD_DLL_DEBUG_EVENT: DWORD = 6;
const UNLOAD_DLL_DEBUG_EVENT: DWORD = 7;
const OUTPUT_DEBUG_STRING_EVENT: DWORD = 8;
const RIP_EVENT: DWORD = 9;

const INFINITE: DWORD = 0xFFFFFFFF;

// Debug structures
const EXCEPTION_RECORD = extern struct {
    ExceptionCode: DWORD,
    ExceptionFlags: DWORD,
    ExceptionRecord: ?*EXCEPTION_RECORD,
    ExceptionAddress: LPVOID,
    NumberParameters: DWORD,
    ExceptionInformation: [15]usize,
};

const EXCEPTION_DEBUG_INFO = extern struct {
    ExceptionRecord: EXCEPTION_RECORD,
    dwFirstChance: DWORD,
};

const CREATE_THREAD_DEBUG_INFO = extern struct {
    hThread: HANDLE,
    lpThreadLocalBase: LPVOID,
    lpStartAddress: ?*anyopaque, // LPTHREAD_START_ROUTINE
};

const CREATE_PROCESS_DEBUG_INFO = extern struct {
    hFile: HANDLE,
    hProcess: HANDLE,
    hThread: HANDLE,
    lpBaseOfImage: LPVOID,
    dwDebugInfoFileOffset: DWORD,
    nDebugInfoSize: DWORD,
    lpThreadLocalBase: LPVOID,
    lpStartAddress: ?*anyopaque, // LPTHREAD_START_ROUTINE
    lpImageName: LPVOID,
    fUnicode: WORD,
};

const EXIT_THREAD_DEBUG_INFO = extern struct {
    dwExitCode: DWORD,
};

const EXIT_PROCESS_DEBUG_INFO = extern struct {
    dwExitCode: DWORD,
};

const LOAD_DLL_DEBUG_INFO = extern struct {
    hFile: HANDLE,
    lpBaseOfDll: LPVOID,
    dwDebugInfoFileOffset: DWORD,
    nDebugInfoSize: DWORD,
    lpImageName: LPVOID,
    fUnicode: WORD,
};

const UNLOAD_DLL_DEBUG_INFO = extern struct {
    lpBaseOfDll: LPVOID,
};

const OUTPUT_DEBUG_STRING_INFO = extern struct {
    lpDebugStringData: LPVOID,
    fUnicode: WORD,
    nDebugStringLength: WORD,
};

const RIP_INFO = extern struct {
    dwError: DWORD,
    dwType: DWORD,
};

// Union for debug event data
const DEBUG_EVENT_UNION = extern union {
    Exception: EXCEPTION_DEBUG_INFO,
    CreateThread: CREATE_THREAD_DEBUG_INFO,
    CreateProcessInfo: CREATE_PROCESS_DEBUG_INFO,
    ExitThread: EXIT_THREAD_DEBUG_INFO,
    ExitProcess: EXIT_PROCESS_DEBUG_INFO,
    LoadDll: LOAD_DLL_DEBUG_INFO,
    UnloadDll: UNLOAD_DLL_DEBUG_INFO,
    DebugString: OUTPUT_DEBUG_STRING_INFO,
    RipInfo: RIP_INFO,
};

const DEBUG_EVENT = extern struct {
    dwDebugEventCode: DWORD,
    dwProcessId: DWORD,
    dwThreadId: DWORD,
    u: DEBUG_EVENT_UNION,
};

// Zig equivalent of Rust DebugEvent enum
pub const DebugEvent = union(enum) {
    Exception: struct { first_chance: bool, exception_code: i32 },
    CreateProcess: struct { exe_name: ?[]const u8, exe_base: u64 },
    CreateThread: struct { thread_id: u32 },
    ExitThread: struct { thread_id: u32 },
    LoadModule: struct { module_name: ?[]const u8, module_base: u64 },
    OutputDebugString: []const u8,
    ExitProcess,
    Other: []const u8,
    
    pub fn deinit(self: DebugEvent, allocator: std.mem.Allocator) void {
        switch (self) {
            .CreateProcess => |cp| {
                if (cp.exe_name) |name| {
                    allocator.free(name);
                }
            },
            .LoadModule => |lm| {
                if (lm.module_name) |name| {
                    allocator.free(name);
                }
            },
            .OutputDebugString => |s| {
                allocator.free(s);
            },
            .Other => |s| {
                allocator.free(s);
            },
            else => {},
        }
    }
};

pub const EventContext = struct {
    process_id: u32,
    thread_id: u32,
};

// Helper function to extract filename from full path
fn extractFilename(allocator: std.mem.Allocator, full_path: []const u16) ?[]u8 {
    // Convert UTF-16 to UTF-8 first
    const utf8_path = std.unicode.utf16LeToUtf8Alloc(allocator, full_path) catch return null;
    defer allocator.free(utf8_path);
    
    // Find the last backslash or forward slash
    var last_sep: ?usize = null;
    for (utf8_path, 0..) |c, i| {
        if (c == '\\' or c == '/') {
            last_sep = i;
        }
    }
    
    const filename = if (last_sep) |sep| utf8_path[sep + 1..] else utf8_path;
    
    // Allocate and copy the filename
    const result = allocator.alloc(u8, filename.len) catch return null;
    @memcpy(result, filename);
    return result;
}

// Note: These functions need a MemorySource, but we don't have it in the event context yet
// TODO: Refactor to pass MemorySource to waitForNextDebugEvent
fn readMemoryStringIndirect(mem_source: memory.MemorySource, allocator: std.mem.Allocator, address: u64, max_len: usize, is_wide: bool) ?[]u8 {
    return memory.readMemoryStringIndirect(mem_source, address, max_len, is_wide, allocator) catch null;
}

fn readMemoryString(mem_source: memory.MemorySource, allocator: std.mem.Allocator, address: u64, len: usize, is_wide: bool) ?[]u8 {
    return memory.readMemoryString(mem_source, address, len, is_wide, allocator) catch null;
}

// TODO: Add MemorySource parameter when integrating with main debugger loop
pub fn waitForNextDebugEvent(allocator: std.mem.Allocator, mem_source: ?memory.MemorySource) !struct { EventContext, DebugEvent } {
    var debug_event = std.mem.zeroes(DEBUG_EVENT);
    
    const result = WaitForDebugEventEx(&debug_event, INFINITE);
    if (result == 0) {
        return error.WaitForDebugEventFailed;
    }
    
    const ctx = EventContext{
        .process_id = debug_event.dwProcessId,
        .thread_id = debug_event.dwThreadId,
    };
    
    const event = switch (debug_event.dwDebugEventCode) {
        EXCEPTION_DEBUG_EVENT => blk: {
            const code = debug_event.u.Exception.ExceptionRecord.ExceptionCode;
            const first_chance = debug_event.u.Exception.dwFirstChance != 0;
            break :blk DebugEvent{ .Exception = .{ 
                .first_chance = first_chance, 
                .exception_code = @bitCast(code)
            }};
        },
        CREATE_THREAD_DEBUG_EVENT => blk: {
            const create_thread = debug_event.u.CreateThread;
            const thread_id = GetThreadId(create_thread.hThread);
            _ = CloseHandle(create_thread.hThread);
            break :blk DebugEvent{ .CreateThread = .{ .thread_id = thread_id }};
        },
        EXIT_THREAD_DEBUG_EVENT => DebugEvent{ .ExitThread = .{ .thread_id = debug_event.dwThreadId }},
        CREATE_PROCESS_DEBUG_EVENT => blk: {
            const create_process = debug_event.u.CreateProcessInfo;
            const exe_base = @intFromPtr(create_process.lpBaseOfImage);
            
            var exe_name: ?[]u8 = null;
            if (create_process.hFile != windows.INVALID_HANDLE_VALUE) {
                var name_buffer: [260]u16 = undefined;
                const name_len = GetFinalPathNameByHandleW(create_process.hFile, &name_buffer, 260, 0);
                if (name_len != 0 and name_len < 260) {
                    exe_name = extractFilename(allocator, name_buffer[0..name_len]);
                }
            }
            
            break :blk DebugEvent{ .CreateProcess = .{ .exe_name = exe_name, .exe_base = exe_base }};
        },
        EXIT_PROCESS_DEBUG_EVENT => DebugEvent.ExitProcess,
        LOAD_DLL_DEBUG_EVENT => blk: {
            const load_dll = debug_event.u.LoadDll;
            const module_base = @intFromPtr(load_dll.lpBaseOfDll);
            
            const module_name = if (load_dll.lpImageName != null and mem_source != null) blk2: {
                const is_wide = load_dll.fUnicode != 0;
                break :blk2 readMemoryStringIndirect(mem_source.?, allocator, @intFromPtr(load_dll.lpImageName), 260, is_wide);
            } else null;
            
            break :blk DebugEvent{ .LoadModule = .{ .module_name = module_name, .module_base = module_base }};
        },
        UNLOAD_DLL_DEBUG_EVENT => blk: {
            const msg = allocator.dupe(u8, "UnloadDll") catch "UnloadDll";
            break :blk DebugEvent{ .Other = msg };
        },
        OUTPUT_DEBUG_STRING_EVENT => blk: {
            const debug_string_info = debug_event.u.DebugString;
            const is_wide = debug_string_info.fUnicode != 0;
            const address = @intFromPtr(debug_string_info.lpDebugStringData);
            const len = debug_string_info.nDebugStringLength;
            
            const debug_string = if (mem_source != null) readMemoryString(mem_source.?, allocator, address, len, is_wide) else null;
            
            if (debug_string) |ds| {
                break :blk DebugEvent{ .OutputDebugString = ds };
            } else {
                const msg = allocator.dupe(u8, "Failed to read debug string") catch "Failed to read debug string";
                break :blk DebugEvent{ .Other = msg };
            }
        },
        RIP_EVENT => blk: {
            const msg = allocator.dupe(u8, "RipEvent") catch "RipEvent";
            break :blk DebugEvent{ .Other = msg };
        },
        else => blk: {
            const msg = std.fmt.allocPrint(allocator, "Unknown debug event: {any}", .{debug_event.dwDebugEventCode}) catch "Unknown debug event";
            break :blk DebugEvent{ .Other = msg };
        },
    };
    
    return .{ ctx, event };
}