const std = @import("std");
const builtin = @import("builtin");
const print = std.debug.print;
const windows = std.os.windows;
const WINAPI = windows.WINAPI;

const event = @import("event.zig");
const memory = @import("memory.zig");
const process = @import("process.zig");
// TODO: Import remaining modules when ported
// const breakpoint = @import("breakpoint.zig");
// const command = @import("command.zig");
// const eval = @import("eval.zig");
// const registers = @import("registers.zig");
// const stack = @import("stack.zig");
const util = @import("util.zig");

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
extern "kernel32" fn OpenThread(
    dwDesiredAccess: DWORD,
    bInheritHandle: BOOL,
    dwThreadId: DWORD,
) callconv(WINAPI) HANDLE;
extern "kernel32" fn GetThreadContext(hThread: HANDLE, lpContext: *util.CONTEXT) callconv(WINAPI) BOOL;
extern "kernel32" fn SetThreadContext(hThread: HANDLE, lpContext: *const util.CONTEXT) callconv(WINAPI) BOOL;
extern "kernel32" fn ContinueDebugEvent(
    dwProcessId: DWORD,
    dwThreadId: DWORD,
    dwContinueStatus: DWORD,
) callconv(WINAPI) BOOL;

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

// Thread access rights
const THREAD_GET_CONTEXT: DWORD = 0x0008;
const THREAD_SET_CONTEXT: DWORD = 0x0010;

// Debug continuation status
const DBG_CONTINUE: DWORD = 0x00010002;
const DBG_EXCEPTION_NOT_HANDLED: DWORD = 0x80010001;

// Exception codes
const EXCEPTION_SINGLE_STEP: i32 = @bitCast(@as(u32, 0x80000004));

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

fn loadModuleAtAddress(proc: *process.Process, mem_source: memory.MemorySource, base_address: u64, module_name: ?[]const u8) void {
    _ = proc.addModule(base_address, module_name, mem_source) catch |err| {
        print("Failed to add module at 0x{x}: {any}\n", .{ base_address, err });
        return;
    };

    const name = module_name orelse "unknown";
    print("LoadDll: {x}   {s}\n", .{ base_address, name });
}

fn mainDebuggerLoop(process_handle: HANDLE, allocator: std.mem.Allocator) !void {
    var expect_step_exception = false;
    const mem_source = memory.makeLiveMemorySource(process_handle, allocator) catch |err| {
        print("Failed to create memory source: {any}\n", .{err});
        return;
    };
    defer mem_source.deinit(allocator);

    var proc = process.Process.init(allocator);
    defer proc.deinit();

    // TODO: Add breakpoint manager when breakpoint.zig is ported
    // var breakpoints = BreakpointManager.init();

    while (true) {
        const event_result = event.waitForNextDebugEvent(allocator, mem_source) catch |err| {
            print("Error waiting for debug event: {any}\n", .{err});
            break;
        };
        const event_context = event_result[0];
        const debug_event = event_result[1];
        defer debug_event.deinit(allocator);

        // Get thread context
        const thread_handle = util.AutoClosedHandle.init(OpenThread(
            THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
            FALSE,
            event_context.thread_id,
        ));
        defer {
            var handle = thread_handle;
            handle.deinit();
        }

        if (thread_handle.get() == windows.INVALID_HANDLE_VALUE) {
            print("Failed to open thread {any}\n", .{event_context.thread_id});
            continue;
        }

        var ctx = util.AlignedContext{ .context = std.mem.zeroes(util.CONTEXT) };
        ctx.context.ContextFlags = util.CONTEXT_ALL;
        const get_ctx_result = GetThreadContext(thread_handle.get(), &ctx.context);
        if (get_ctx_result == 0) {
            print("GetThreadContext failed\n", .{});
            continue;
        }

        var continue_status = DBG_CONTINUE;
        var is_exit = false;

        switch (debug_event) {
            .Exception => |exc| {
                const chance_string = if (exc.first_chance) "first chance" else "second chance";

                if (expect_step_exception and exc.exception_code == EXCEPTION_SINGLE_STEP) {
                    expect_step_exception = false;
                    continue_status = DBG_CONTINUE;
                } else {
                    // TODO: Add breakpoint checking when breakpoint.zig is ported
                    // } else if (breakpoints.wasBreakpointHit(&ctx.context)) |bp_index| {
                    //     print("Breakpoint {} hit\n", .{bp_index});
                    //     continue_status = DBG_CONTINUE;
                    print("Exception code {x} ({s})\n", .{ @as(u32, @bitCast(exc.exception_code)), chance_string });
                    continue_status = DBG_EXCEPTION_NOT_HANDLED;
                }
            },
            .CreateProcess => |cp| {
                loadModuleAtAddress(&proc, mem_source, cp.exe_base, cp.exe_name);
                proc.addThread(event_context.thread_id) catch {};
            },
            .CreateThread => |ct| {
                proc.addThread(ct.thread_id) catch {};
                print("Thread created: {x}\n", .{ct.thread_id});
            },
            .ExitThread => |et| {
                proc.removeThread(et.thread_id);
                print("Thread exited: {x}\n", .{et.thread_id});
            },
            .LoadModule => |lm| {
                loadModuleAtAddress(&proc, mem_source, lm.module_base, lm.module_name);
            },
            .OutputDebugString => |debug_string| {
                print("DebugOut: {s}\n", .{debug_string});
            },
            .Other => |msg| {
                print("{s}\n", .{msg});
            },
            .ExitProcess => {
                is_exit = true;
                print("ExitProcess\n", .{});
            },
        }

        // For now, automatically continue execution
        // TODO: Add command processing when command.zig is ported
        var continue_execution = true;

        while (!continue_execution) {
            // TODO: Add command processing here
            print("[{x}] 0x{x:0>16}\n", .{ event_context.thread_id, ctx.context.Rip });

            // For now, just continue
            continue_execution = true;
        }

        if (is_exit) {
            break;
        }

        // TODO: Apply breakpoints when breakpoint.zig is ported
        // breakpoints.applyBreakpoints(&proc, event_context.thread_id, mem_source);

        const continue_result = ContinueDebugEvent(
            event_context.process_id,
            event_context.thread_id,
            continue_status,
        );

        if (continue_result == 0) {
            print("ContinueDebugEvent failed\n", .{});
            break;
        }
    }
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
        print("CreateProcessW failed with error: {any}\n", .{windows.kernel32.GetLastError()});
        return;
    }

    // Close thread handle (we don't need it)
    _ = CloseHandle(pi.hThread);

    // Enter debugger loop
    mainDebuggerLoop(pi.hProcess, allocator) catch |err| {
        print("Debugger loop failed: {any}\n", .{err});
    };

    // Clean up process handle
    _ = CloseHandle(pi.hProcess);
}
