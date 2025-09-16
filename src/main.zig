const std = @import("std");
const windows = std.os.windows;
const print = std.debug.print;
const Allocator = std.mem.Allocator;

// Import modules
const util = @import("util.zig");
const event = @import("event.zig");

// Windows API constants
const DEBUG_ONLY_THIS_PROCESS = 0x00000002;
const CREATE_NEW_CONSOLE = 0x00000010;
const FALSE = windows.FALSE;

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

extern "kernel32" fn CloseHandle(hObject: windows.HANDLE) callconv(windows.WINAPI) windows.BOOL;


pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const target_command_line = util.parseCommandLine(allocator) catch |err| {
        const error_msg = switch (err) {
            error.EmptyCommandLine => "Command line was empty",
            error.NoArgumentsFound => "No arguments found",
            error.OutOfMemory => "Out of memory",
        };
        util.showUsage(error_msg);
        return;
    };
    defer allocator.free(target_command_line);

    // Convert to UTF-8 for display
    const utf8_cmd_line = std.unicode.utf16LeToUtf8Alloc(allocator, target_command_line[0 .. target_command_line.len - 1]) catch |err| {
        print("Failed to convert command line to UTF-8: {any}\n", .{err});
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
    try event.mainDebuggerLoop(allocator, pi.hProcess);

    // Clean up
    _ = CloseHandle(pi.hProcess);
}
