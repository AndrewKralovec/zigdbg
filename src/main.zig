const std = @import("std");
const windows = std.os.windows;
const print = std.debug.print;
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;

// Windows API constants
const INFINITE = windows.INFINITE;
const DEBUG_ONLY_THIS_PROCESS = 0x00000002;
const CREATE_NEW_CONSOLE = 0x00000010;
const FALSE = windows.FALSE;

// Debug event codes
const EXCEPTION_DEBUG_EVENT = 1;
const CREATE_THREAD_DEBUG_EVENT = 2;
const CREATE_PROCESS_DEBUG_EVENT = 3;
const EXIT_THREAD_DEBUG_EVENT = 4;
const EXIT_PROCESS_DEBUG_EVENT = 5;
const LOAD_DLL_DEBUG_EVENT = 6;
const UNLOAD_DLL_DEBUG_EVENT = 7;
const OUTPUT_DEBUG_STRING_EVENT = 8;
const RIP_EVENT = 9;

const DBG_EXCEPTION_NOT_HANDLED = 0x80010001;

// Debug event structures
const DEBUG_EVENT = extern struct {
    dwDebugEventCode: windows.DWORD,
    dwProcessId: windows.DWORD,
    dwThreadId: windows.DWORD,
    u: extern union {
        Exception: EXCEPTION_DEBUG_INFO,
        CreateThread: CREATE_THREAD_DEBUG_INFO,
        CreateProcessInfo: CREATE_PROCESS_DEBUG_INFO,
        ExitThread: EXIT_THREAD_DEBUG_INFO,
        ExitProcess: EXIT_PROCESS_DEBUG_INFO,
        LoadDll: LOAD_DLL_DEBUG_INFO,
        UnloadDll: UNLOAD_DLL_DEBUG_INFO,
        DebugString: OUTPUT_DEBUG_STRING_INFO,
        RipInfo: RIP_INFO,
    },
};

const EXCEPTION_DEBUG_INFO = extern struct {
    ExceptionRecord: EXCEPTION_RECORD,
    dwFirstChance: windows.DWORD,
};

const EXCEPTION_RECORD = extern struct {
    ExceptionCode: windows.DWORD,
    ExceptionFlags: windows.DWORD,
    ExceptionRecord: ?*EXCEPTION_RECORD,
    ExceptionAddress: ?*anyopaque,
    NumberParameters: windows.DWORD,
    ExceptionInformation: [15]usize,
};

const CREATE_THREAD_DEBUG_INFO = extern struct {
    hThread: windows.HANDLE,
    lpThreadLocalBase: ?*anyopaque,
    lpStartAddress: ?*anyopaque,
};

const CREATE_PROCESS_DEBUG_INFO = extern struct {
    hFile: windows.HANDLE,
    hProcess: windows.HANDLE,
    hThread: windows.HANDLE,
    lpBaseOfImage: ?*anyopaque,
    dwDebugInfoFileOffset: windows.DWORD,
    nDebugInfoSize: windows.DWORD,
    lpThreadLocalBase: ?*anyopaque,
    lpStartAddress: ?*anyopaque,
    lpImageName: ?*anyopaque,
    fUnicode: windows.WORD,
};

const EXIT_THREAD_DEBUG_INFO = extern struct {
    dwExitCode: windows.DWORD,
};

const EXIT_PROCESS_DEBUG_INFO = extern struct {
    dwExitCode: windows.DWORD,
};

const LOAD_DLL_DEBUG_INFO = extern struct {
    hFile: windows.HANDLE,
    lpBaseOfDll: ?*anyopaque,
    dwDebugInfoFileOffset: windows.DWORD,
    nDebugInfoSize: windows.DWORD,
    lpImageName: ?*anyopaque,
    fUnicode: windows.WORD,
};

const UNLOAD_DLL_DEBUG_INFO = extern struct {
    lpBaseOfDll: ?*anyopaque,
};

const OUTPUT_DEBUG_STRING_INFO = extern struct {
    lpDebugStringData: [*:0]u8,
    fUnicode: windows.WORD,
    nDebugStringLength: windows.WORD,
};

const RIP_INFO = extern struct {
    dwError: windows.DWORD,
    dwType: windows.DWORD,
};

const STARTUPINFOEXW = extern struct {
    StartupInfo: STARTUPINFOW,
    lpAttributeList: ?*anyopaque,
};

const STARTUPINFOW = extern struct {
    cb: windows.DWORD,
    lpReserved: ?[*:0]u16,
    lpDesktop: ?[*:0]u16,
    lpTitle: ?[*:0]u16,
    dwX: windows.DWORD,
    dwY: windows.DWORD,
    dwXSize: windows.DWORD,
    dwYSize: windows.DWORD,
    dwXCountChars: windows.DWORD,
    dwYCountChars: windows.DWORD,
    dwFillAttribute: windows.DWORD,
    dwFlags: windows.DWORD,
    wShowWindow: windows.WORD,
    cbReserved2: windows.WORD,
    lpReserved2: ?[*]u8,
    hStdInput: windows.HANDLE,
    hStdOutput: windows.HANDLE,
    hStdError: windows.HANDLE,
};

const PROCESS_INFORMATION = extern struct {
    hProcess: windows.HANDLE,
    hThread: windows.HANDLE,
    dwProcessId: windows.DWORD,
    dwThreadId: windows.DWORD,
};

// External Windows API functions
extern "kernel32" fn GetCommandLineW() callconv(windows.WINAPI) [*:0]u16;

extern "kernel32" fn CreateProcessW(
    lpApplicationName: ?[*:0]const u16,
    lpCommandLine: ?[*:0]u16,
    lpProcessAttributes: ?*anyopaque,
    lpThreadAttributes: ?*anyopaque,
    bInheritHandles: windows.BOOL,
    dwCreationFlags: windows.DWORD,
    lpEnvironment: ?*anyopaque,
    lpCurrentDirectory: ?[*:0]const u16,
    lpStartupInfo: *STARTUPINFOW,
    lpProcessInformation: *PROCESS_INFORMATION,
) callconv(windows.WINAPI) windows.BOOL;

extern "kernel32" fn WaitForDebugEventEx(
    lpDebugEvent: *DEBUG_EVENT,
    dwMilliseconds: windows.DWORD,
) callconv(windows.WINAPI) windows.BOOL;

extern "kernel32" fn ContinueDebugEvent(
    dwProcessId: windows.DWORD,
    dwThreadId: windows.DWORD,
    dwContinueStatus: windows.DWORD,
) callconv(windows.WINAPI) windows.BOOL;

extern "kernel32" fn CloseHandle(hObject: windows.HANDLE) callconv(windows.WINAPI) windows.BOOL;

// Helper function to calculate length of null-terminated wide string
fn wcslen(ptr: [*:0]const u16) usize {
    var len: usize = 0;
    while (ptr[len] != 0) {
        len += 1;
    }
    return len;
}

fn showUsage(error_message: []const u8) void {
    print("Error: {s}\n", .{error_message});
    print("Usage: zig-debugger <Command Line>\n", .{});
}

// Parse command line to extract the target process command line
// This mimics the Rust version's behavior of preserving the original UTF-16 command line
fn parseCommandLine(allocator: Allocator) ![]u16 {
    const cmd_line_ptr = GetCommandLineW();
    const cmd_line_len = wcslen(cmd_line_ptr);
    const cmd_line = cmd_line_ptr[0..cmd_line_len];

    if (cmd_line.len == 0) {
        return error.EmptyCommandLine;
    }

    var i: usize = 0;
    const first_char = cmd_line[0];

    // If the first character is a quote, find the matching end quote. Otherwise, find the first space.
    const end_char: u16 = if (first_char == '"') '"' else ' ';

    // Skip the first character
    i = 1;

    // Find the end of the executable name
    while (i < cmd_line.len and cmd_line[i] != end_char) {
        i += 1;
    }

    if (i >= cmd_line.len) {
        return error.NoArgumentsFound;
    }

    // Skip the end character (quote or space)
    i += 1;

    // Skip any whitespace
    while (i < cmd_line.len and cmd_line[i] == ' ') {
        i += 1;
    }

    if (i >= cmd_line.len) {
        return error.NoArgumentsFound;
    }

    // Copy the remaining command line arguments
    const remaining_len = cmd_line.len - i;
    var result = try allocator.alloc(u16, remaining_len + 1); // +1 for null terminator
    @memcpy(result[0..remaining_len], cmd_line[i..]);
    result[remaining_len] = 0; // Null terminate

    return result;
}

fn mainDebuggerLoop() void {
    while (true) {
        var debug_event: DEBUG_EVENT = std.mem.zeroes(DEBUG_EVENT);

        const wait_result = WaitForDebugEventEx(&debug_event, INFINITE);
        if (wait_result == 0) {
            print("WaitForDebugEventEx failed\n", .{});
            break;
        }

        switch (debug_event.dwDebugEventCode) {
            EXCEPTION_DEBUG_EVENT => print("Exception\n", .{}),
            CREATE_THREAD_DEBUG_EVENT => print("CreateThread\n", .{}),
            CREATE_PROCESS_DEBUG_EVENT => print("CreateProcess\n", .{}),
            EXIT_THREAD_DEBUG_EVENT => print("ExitThread\n", .{}),
            EXIT_PROCESS_DEBUG_EVENT => print("ExitProcess\n", .{}),
            LOAD_DLL_DEBUG_EVENT => print("LoadDll\n", .{}),
            UNLOAD_DLL_DEBUG_EVENT => print("UnloadDll\n", .{}),
            OUTPUT_DEBUG_STRING_EVENT => print("OutputDebugString\n", .{}),
            RIP_EVENT => print("RipEvent\n", .{}),
            else => {
                print("Unexpected debug event: {}\n", .{debug_event.dwDebugEventCode});
                break;
            },
        }

        if (debug_event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            break;
        }

        _ = ContinueDebugEvent(
            debug_event.dwProcessId,
            debug_event.dwThreadId,
            DBG_EXCEPTION_NOT_HANDLED,
        );
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const target_command_line = parseCommandLine(allocator) catch |err| {
        const error_msg = switch (err) {
            error.EmptyCommandLine => "Command line was empty",
            error.NoArgumentsFound => "No arguments found",
            error.OutOfMemory => "Out of memory",
        };
        showUsage(error_msg);
        return;
    };
    defer allocator.free(target_command_line);

    // Convert to UTF-8 for display (like the Rust version does with from_utf16_lossy)
    const utf8_cmd_line = std.unicode.utf16LeToUtf8Alloc(allocator, target_command_line[0 .. target_command_line.len - 1]) catch |err| {
        print("Failed to convert command line to UTF-8: {}\n", .{err});
        return;
    };
    defer allocator.free(utf8_cmd_line);

    print("Command line was: '{s}'\n", .{utf8_cmd_line});

    var si = std.mem.zeroes(STARTUPINFOEXW);
    si.StartupInfo.cb = @sizeOf(STARTUPINFOEXW);
    var pi = std.mem.zeroes(PROCESS_INFORMATION);

    const create_result = CreateProcessW(
        null, // lpApplicationName
        @ptrCast(target_command_line.ptr), // lpCommandLine (mutable)
        null, // lpProcessAttributes
        null, // lpThreadAttributes
        FALSE, // bInheritHandles
        DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE, // dwCreationFlags
        null, // lpEnvironment
        null, // lpCurrentDirectory
        &si.StartupInfo, // lpStartupInfo
        &pi, // lpProcessInformation
    );

    if (create_result == 0) {
        const err = windows.kernel32.GetLastError();
        print("CreateProcessW failed with error: {}\n", .{err});
        return;
    }

    // Close the thread handle as we don't need it
    _ = CloseHandle(pi.hThread);

    // Run the main debugger loop
    mainDebuggerLoop();

    // Clean up
    _ = CloseHandle(pi.hProcess);
}
