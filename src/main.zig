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

const DBG_CONTINUE = 0x00010002;
const DBG_EXCEPTION_NOT_HANDLED = 0x80010001;

// Exception codes
const EXCEPTION_SINGLE_STEP = 0x80000004;

// Thread access rights
const THREAD_GET_CONTEXT = 0x0008;
const THREAD_SET_CONTEXT = 0x0010;

// Context flags for x64
const CONTEXT_AMD64 = 0x00100000;
const CONTEXT_CONTROL = CONTEXT_AMD64 | 0x00000001;
const CONTEXT_INTEGER = CONTEXT_AMD64 | 0x00000002;
const CONTEXT_SEGMENTS = CONTEXT_AMD64 | 0x00000004;
const CONTEXT_FLOATING_POINT = CONTEXT_AMD64 | 0x00000008;
const CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x00000010;
const CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS;

// Trap flag for single stepping
const TRAP_FLAG = 1 << 8;

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

// 16-byte aligned context structure for x64
const AlignedContext = struct {
    context: windows.CONTEXT,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .context = std.mem.zeroes(windows.CONTEXT),
        };
    }
};

// Auto-closing handle wrapper
const AutoClosedHandle = struct {
    handle: windows.HANDLE,

    const Self = @This();

    pub fn init(handle: windows.HANDLE) Self {
        return Self{ .handle = handle };
    }

    pub fn deinit(self: *Self) void {
        _ = CloseHandle(self.handle);
    }

    pub fn getHandle(self: *const Self) windows.HANDLE {
        return self.handle;
    }
};

// Command enumeration
const Command = enum {
    StepInto, // t
    Go, // g
    DisplayRegisters, // r
    Quit, // q
    Unknown,
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

extern "kernel32" fn OpenThread(
    dwDesiredAccess: windows.DWORD,
    bInheritHandle: windows.BOOL,
    dwThreadId: windows.DWORD,
) callconv(windows.WINAPI) windows.HANDLE;

extern "kernel32" fn GetThreadContext(
    hThread: windows.HANDLE,
    lpContext: *windows.CONTEXT,
) callconv(windows.WINAPI) windows.BOOL;

extern "kernel32" fn SetThreadContext(
    hThread: windows.HANDLE,
    lpContext: *const windows.CONTEXT,
) callconv(windows.WINAPI) windows.BOOL;

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

// Simple command parsing (replacing rust-sitter)
fn readCommand() Command {
    const stdin = std.io.getStdIn().reader();

    while (true) {
        print("> ", .{});
        // Flush stdout to ensure the prompt appears
        // std.io.getStdOut().writer().context.flush() catch {};

        var input_buffer: [256]u8 = undefined;
        if (stdin.readUntilDelimiterOrEof(&input_buffer, '\n')) |maybe_input| {
            if (maybe_input) |input| {
                const trimmed = std.mem.trim(u8, input, " \t\r\n");

                if (trimmed.len == 0) continue;

                if (std.mem.eql(u8, trimmed, "t")) {
                    return Command.StepInto;
                } else if (std.mem.eql(u8, trimmed, "g")) {
                    return Command.Go;
                } else if (std.mem.eql(u8, trimmed, "r")) {
                    return Command.DisplayRegisters;
                } else if (std.mem.eql(u8, trimmed, "q")) {
                    return Command.Quit;
                } else {
                    print("Unknown command: {s}\n", .{trimmed});
                    print("Available commands: t (step), g (go), r (registers), q (quit)\n", .{});
                    continue;
                }
            }
        } else |_| {
            // EOF or error
            return Command.Quit;
        }
    }
}

// Display all registers
fn displayAllRegisters(context: windows.CONTEXT) void {
    // Use explicit "0x" prefix and {x} with padding
    print("rax=0x{x:0>16} rbx=0x{x:0>16} rcx=0x{x:0>16}\n", .{ context.Rax, context.Rbx, context.Rcx });
    print("rdx=0x{x:0>16} rsi=0x{x:0>16} rdi=0x{x:0>16}\n", .{ context.Rdx, context.Rsi, context.Rdi });
    print("rip=0x{x:0>16} rsp=0x{x:0>16} rbp=0x{x:0>16}\n", .{ context.Rip, context.Rsp, context.Rbp });
    print(" r8=0x{x:0>16}  r9=0x{x:0>16} r10=0x{x:0>16}\n", .{ context.R8, context.R9, context.R10 });
    print("r11=0x{x:0>16} r12=0x{x:0>16} r13=0x{x:0>16}\n", .{ context.R11, context.R12, context.R13 });
    print("r14=0x{x:0>16} r15=0x{x:0>16} eflags=0x{x:0>8}\n", .{ context.R14, context.R15, context.EFlags });
}

fn mainDebuggerLoop(_: windows.HANDLE) void {
    var expect_step_exception = false;

    while (true) {
        var debug_event = std.mem.zeroes(DEBUG_EVENT);

        const wait_result = WaitForDebugEventEx(&debug_event, INFINITE);
        if (wait_result == 0) {
            print("WaitForDebugEventEx failed\n", .{});
            break;
        }

        var continue_status: windows.DWORD = DBG_CONTINUE;

        switch (debug_event.dwDebugEventCode) {
            EXCEPTION_DEBUG_EVENT => {
                const code = debug_event.u.Exception.ExceptionRecord.ExceptionCode;
                const first_chance = debug_event.u.Exception.dwFirstChance;
                const chance_string = if (first_chance == 0) "second chance" else "first chance";

                if (expect_step_exception and code == EXCEPTION_SINGLE_STEP) {
                    expect_step_exception = false;
                    continue_status = DBG_CONTINUE;
                } else {
                    print("Exception code {x} ({s})\n", .{ code, chance_string });
                    continue_status = DBG_EXCEPTION_NOT_HANDLED;
                }
            },
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

        // Open thread handle for reading/writing context
        var thread = AutoClosedHandle.init(OpenThread(
            THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
            FALSE,
            debug_event.dwThreadId,
        ));
        defer thread.deinit();

        if (thread.getHandle() == windows.INVALID_HANDLE_VALUE) {
            print("Failed to open thread\n", .{});
            continue;
        }

        // Get thread context
        var ctx = AlignedContext.init();
        ctx.context.ContextFlags = CONTEXT_ALL;

        const get_context_result = GetThreadContext(thread.getHandle(), &ctx.context);
        if (get_context_result == 0) {
            print("GetThreadContext failed\n", .{});
            continue;
        }

        var continue_execution = false;

        while (!continue_execution) {
            print("[{x:0>8}] 0x{x:0>16}\n", .{ debug_event.dwThreadId, ctx.context.Rip });

            const cmd = readCommand();

            switch (cmd) {
                Command.StepInto => {
                    ctx.context.EFlags |= TRAP_FLAG;
                    const set_context_result = SetThreadContext(thread.getHandle(), &ctx.context);
                    if (set_context_result == 0) {
                        print("SetThreadContext failed\n", .{});
                        continue;
                    }
                    expect_step_exception = true;
                    continue_execution = true;
                },
                Command.Go => {
                    continue_execution = true;
                },
                Command.DisplayRegisters => {
                    displayAllRegisters(ctx.context);
                },
                Command.Quit => {
                    // The process will be terminated since we didn't detach
                    return;
                },
                Command.Unknown => {
                    // This shouldn't happen with our current implementation
                    continue;
                },
            }
        }

        if (debug_event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            break;
        }

        _ = ContinueDebugEvent(
            debug_event.dwProcessId,
            debug_event.dwThreadId,
            continue_status,
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

    // Convert to UTF-8 for display
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
    mainDebuggerLoop(pi.hProcess);

    // Clean up
    _ = CloseHandle(pi.hProcess);
}
