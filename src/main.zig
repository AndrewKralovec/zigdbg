const std = @import("std");
const builtin = @import("builtin");
const print = std.debug.print;
const windows = std.os.windows;
const WINAPI = windows.WINAPI;

// TODO: Import modules when they are ported
// const event = @import("event.zig");
// const memory = @import("memory.zig");
// const process = @import("process.zig");
// const breakpoint = @import("breakpoint.zig");
// const command = @import("command.zig");
// const eval = @import("eval.zig");
// const registers = @import("registers.zig");
// const stack = @import("stack.zig");
// const util = @import("util.zig");

const TRAP_FLAG: u32 = 1 << 8;

// Windows API constants and types
const HANDLE = windows.HANDLE;
const DWORD = windows.DWORD;
const BOOL = windows.BOOL;
const LPVOID = ?*anyopaque;
const LPCWSTR = [*:0]const u16;
const LPWSTR = [*:0]u16;

// Windows API functions we need
extern "kernel32" fn GetCommandLineW() LPWSTR;
extern "kernel32" fn CreateProcessW(
    lpApplicationName: ?LPCWSTR,
    lpCommandLine: ?LPWSTR,
    lpProcessAttributes: ?*anyopaque,
    lpThreadAttributes: ?*anyopaque,
    bInheritHandles: BOOL,
    dwCreationFlags: DWORD,
    lpEnvironment: ?*anyopaque,
    lpCurrentDirectory: ?LPCWSTR,
    lpStartupInfo: *STARTUPINFOEXW,
    lpProcessInformation: *PROCESS_INFORMATION,
) callconv(WINAPI) BOOL;

extern "kernel32" fn CloseHandle(hObject: HANDLE) callconv(WINAPI) BOOL;

// Windows structures
const STARTUPINFOEXW = extern struct {
    StartupInfo: STARTUPINFOW,
    lpAttributeList: ?*anyopaque,
};

const STARTUPINFOW = extern struct {
    cb: DWORD,
    lpReserved: ?LPWSTR,
    lpDesktop: ?LPWSTR,
    lpTitle: ?LPWSTR,
    dwX: DWORD,
    dwY: DWORD,
    dwXSize: DWORD,
    dwYSize: DWORD,
    dwXCountChars: DWORD,
    dwYCountChars: DWORD,
    dwFillAttribute: DWORD,
    dwFlags: DWORD,
    wShowWindow: u16,
    cbReserved2: u16,
    lpReserved2: ?*u8,
    hStdInput: HANDLE,
    hStdOutput: HANDLE,
    hStdError: HANDLE,
};

const PROCESS_INFORMATION = extern struct {
    hProcess: HANDLE,
    hThread: HANDLE,
    dwProcessId: DWORD,
    dwThreadId: DWORD,
};

// Process creation flags
const DEBUG_ONLY_THIS_PROCESS: DWORD = 0x00000002;
const CREATE_NEW_CONSOLE: DWORD = 0x00000010;

const FALSE: BOOL = 0;

fn showUsage(error_message: []const u8) void {
    print("Error: {s}\n", .{error_message});
    print("Usage: DbgZig <Command Line>\n", .{});
}

fn wcslen(ptr: [*:0]const u16) usize {
    var len: usize = 0;
    while (ptr[len] != 0) {
        len += 1;
    }
    return len;
}

// Port of parse_command_line() from Rust
// For now, we only accept the command line of the process to launch
// Q: Why not just convert to UTF8?
// A: There can be cases where this is lossy, and we want to debug as close as possible to normal execution
fn parseCommandLine(allocator: std.mem.Allocator) ![]u16 {
    const cmd_line_ptr = GetCommandLineW();
    const cmd_line_len = wcslen(cmd_line_ptr);
    const cmd_line = cmd_line_ptr[0..cmd_line_len];

    if (cmd_line.len == 0) {
        return error.CommandLineEmpty;
    }

    var iter_index: usize = 0;

    const first = cmd_line[iter_index];
    iter_index += 1;

    // If the first character is a quote, we need to find a matching end quote. Otherwise, the first space.
    const end_char: u16 = if (first == '"') '"' else ' ';

    // Find the end of the first argument (executable name)
    while (iter_index < cmd_line.len) {
        const next = cmd_line[iter_index];
        iter_index += 1;
        if (next == end_char) {
            break;
        }
    }

    if (iter_index >= cmd_line.len) {
        return error.NoArgumentsFound;
    }

    // Skip whitespace
    while (iter_index < cmd_line.len and cmd_line[iter_index] == ' ') {
        iter_index += 1;
    }

    if (iter_index >= cmd_line.len) {
        return error.NoArgumentsFound;
    }

    // Copy the remaining command line (including null terminator)
    const remaining_args = cmd_line[iter_index..];
    var result = try allocator.alloc(u16, remaining_args.len + 1);
    @memcpy(result[0..remaining_args.len], remaining_args);
    result[remaining_args.len] = 0; // Null terminator

    return result;
}

// TODO: Implement when other modules are ported
fn mainDebuggerLoop(process: HANDLE) void {
    _ = process;
    print("TODO: Implement debugger loop - waiting for other modules to be ported\n", .{});

    // For now, just a placeholder that shows we successfully created the process
    print("Process created successfully. Debugger loop not yet implemented.\n", .{});
    print("Need to port: event.zig, memory.zig, process.zig, breakpoint.zig, etc.\n", .{});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const target_command_line = parseCommandLine(allocator) catch |err| {
        const error_message = switch (err) {
            error.CommandLineEmpty => "Command line was empty",
            error.NoArgumentsFound => "No arguments found",
            error.OutOfMemory => "Out of memory",
        };
        showUsage(error_message);
        return;
    };
    defer allocator.free(target_command_line);

    // Convert to null-terminated for display
    const utf8_cmd = std.unicode.utf16LeToUtf8Alloc(allocator, target_command_line[0 .. target_command_line.len - 1]) catch {
        print("Failed to convert command line to UTF-8 for display\n", .{});
        return;
    };
    defer allocator.free(utf8_cmd);

    print("Command line was: '{s}'\n", .{utf8_cmd});

    // Initialize startup info
    var si = std.mem.zeroes(STARTUPINFOEXW);
    si.StartupInfo.cb = @sizeOf(STARTUPINFOEXW);

    var pi: PROCESS_INFORMATION = undefined;

    // Create process with debug flags
    const success = CreateProcessW(
        null, // lpApplicationName
        @ptrCast(target_command_line.ptr), // lpCommandLine (mutable)
        null, // lpProcessAttributes
        null, // lpThreadAttributes
        FALSE, // bInheritHandles
        DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE, // dwCreationFlags
        null, // lpEnvironment
        null, // lpCurrentDirectory
        &si, // lpStartupInfo
        &pi, // lpProcessInformation
    );

    if (success == 0) {
        print("CreateProcessW failed with error: {}\n", .{windows.kernel32.GetLastError()});
        return;
    }

    // Close thread handle (we don't need it)
    _ = CloseHandle(pi.hThread);

    // Enter debugger loop
    mainDebuggerLoop(pi.hProcess);

    // Clean up process handle
    _ = CloseHandle(pi.hProcess);
}
