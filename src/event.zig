const std = @import("std");
const windows = std.os.windows;
const print = std.debug.print;
const Allocator = std.mem.Allocator;

// Import modules
const util = @import("util.zig");
const memory = @import("memory.zig");
const process_mod = @import("process.zig");
const breakpoint = @import("breakpoint.zig");
const stack = @import("stack.zig");
const eval = @import("eval.zig");
const command = @import("command.zig");
const registers = @import("registers.zig");
const name_resolution = @import("./name_resolution.zig");

// Windows API constants
const INFINITE = windows.INFINITE;
const DEBUG_ONLY_THIS_PROCESS = 0x00000002;
const CREATE_NEW_CONSOLE = 0x00000010;
const FALSE = windows.FALSE;

// Debug event codes
pub const EXCEPTION_DEBUG_EVENT = 1;
pub const CREATE_THREAD_DEBUG_EVENT = 2;
pub const CREATE_PROCESS_DEBUG_EVENT = 3;
pub const EXIT_THREAD_DEBUG_EVENT = 4;
pub const EXIT_PROCESS_DEBUG_EVENT = 5;
pub const LOAD_DLL_DEBUG_EVENT = 6;
pub const UNLOAD_DLL_DEBUG_EVENT = 7;
pub const OUTPUT_DEBUG_STRING_EVENT = 8;
pub const RIP_EVENT = 9;

pub const DBG_CONTINUE = 0x00010002;
pub const DBG_EXCEPTION_NOT_HANDLED = 0x80010001;

// Exception codes
pub const EXCEPTION_SINGLE_STEP = 0x80000004;

// Thread access rights
pub const THREAD_GET_CONTEXT = 0x0008;
pub const THREAD_SET_CONTEXT = 0x0010;

// Context flags for x64
pub const CONTEXT_AMD64 = 0x00100000;
pub const CONTEXT_CONTROL = CONTEXT_AMD64 | 0x00000001;
pub const CONTEXT_INTEGER = CONTEXT_AMD64 | 0x00000002;
pub const CONTEXT_SEGMENTS = CONTEXT_AMD64 | 0x00000004;
pub const CONTEXT_FLOATING_POINT = CONTEXT_AMD64 | 0x00000008;
pub const CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x00000010;
pub const CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS;

// Trap flag for single stepping
pub const TRAP_FLAG = 1 << 8;

// Maximum path length for module names
pub const MAX_PATH = 260;

// Debug event structures
pub const DEBUG_EVENT = extern struct {
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

pub const EXCEPTION_DEBUG_INFO = extern struct {
    ExceptionRecord: EXCEPTION_RECORD,
    dwFirstChance: windows.DWORD,
};

pub const EXCEPTION_RECORD = extern struct {
    ExceptionCode: windows.DWORD,
    ExceptionFlags: windows.DWORD,
    ExceptionRecord: ?*EXCEPTION_RECORD,
    ExceptionAddress: ?*anyopaque,
    NumberParameters: windows.DWORD,
    ExceptionInformation: [15]usize,
};

pub const CREATE_THREAD_DEBUG_INFO = extern struct {
    hThread: windows.HANDLE,
    lpThreadLocalBase: ?*anyopaque,
    lpStartAddress: ?*anyopaque,
};

pub const CREATE_PROCESS_DEBUG_INFO = extern struct {
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

pub const EXIT_THREAD_DEBUG_INFO = extern struct {
    dwExitCode: windows.DWORD,
};

pub const EXIT_PROCESS_DEBUG_INFO = extern struct {
    dwExitCode: windows.DWORD,
};

pub const LOAD_DLL_DEBUG_INFO = extern struct {
    hFile: windows.HANDLE,
    lpBaseOfDll: ?*anyopaque,
    dwDebugInfoFileOffset: windows.DWORD,
    nDebugInfoSize: windows.DWORD,
    lpImageName: ?*anyopaque,
    fUnicode: windows.WORD,
};

pub const UNLOAD_DLL_DEBUG_INFO = extern struct {
    lpBaseOfDll: ?*anyopaque,
};

pub const OUTPUT_DEBUG_STRING_INFO = extern struct {
    lpDebugStringData: ?*anyopaque,
    fUnicode: windows.WORD,
    nDebugStringLength: windows.WORD,
};

pub const RIP_INFO = extern struct {
    dwError: windows.DWORD,
    dwType: windows.DWORD,
};

// 16-byte aligned context structure for x64
pub const AlignedContext = struct {
    context: windows.CONTEXT,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .context = std.mem.zeroes(windows.CONTEXT),
        };
    }
};

// Auto-closing handle wrapper
pub const AutoClosedHandle = struct {
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

// External Windows API functions
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

// Display call stack
fn displayCallStack(allocator: Allocator, process_info: *process_mod.Process, process: windows.HANDLE, context: windows.CONTEXT) void {
    var current_context = context;
    var frame_number: u32 = 0;

    print("Call Stack:\n", .{});

    while (frame_number < 50) { // Limit to 50 frames to prevent infinite loops
        // Try to resolve the instruction pointer to a symbol
        if (name_resolution.resolveAddressToName(allocator, current_context.Rip, process_info)) |sym| {
            if (sym) |s| {
                print("{any} 0x{x:0>16} {s}\n", .{ frame_number, current_context.Rsp, s });
                allocator.free(s);
            } else {
                print("{any} 0x{x:0>16} 0x{x:0>16}\n", .{ frame_number, current_context.Rsp, current_context.Rip });
            }
        } else |_| {
            print("{any} 0x{x:0>16} 0x{x:0>16}\n", .{ frame_number, current_context.Rsp, current_context.Rip });
        }

        // Try to unwind to the next frame
        if (stack.unwindContext(allocator, process_info, process, current_context)) |unwound_context| {
            current_context = unwound_context;
            frame_number += 1;
        } else {
            // If structured unwinding fails, try simple frame pointer walking
            if (current_context.Rbp != 0 and current_context.Rbp > current_context.Rsp) {
                const frame_data = memory.readProcessMemoryArray(u64, allocator, process, current_context.Rbp, 2) catch break;
                defer allocator.free(frame_data);

                // frame_data[0] should be the saved RBP, frame_data[1] should be return address
                if (frame_data.len >= 2 and frame_data[1] != 0) {
                    current_context.Rbp = frame_data[0];
                    current_context.Rip = frame_data[1];
                    current_context.Rsp = current_context.Rbp + 16; // Skip saved RBP and return address
                    frame_number += 1;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }
}

pub fn mainDebuggerLoop(allocator: Allocator, process: windows.HANDLE) !void {
    var expect_step_exception = false;
    var process_info = process_mod.Process.init(allocator);
    defer process_info.deinit(allocator);

    var breakpoints = breakpoint.BreakpointManager.init(allocator);
    defer breakpoints.deinit();

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
                    print("Exception code 0x{x:0>4} ({s})\n", .{ code, chance_string });
                    continue_status = DBG_EXCEPTION_NOT_HANDLED;
                }
            },
            CREATE_THREAD_DEBUG_EVENT => {
                print("CreateThread\n", .{});
                _ = process_info.addThread(debug_event.dwThreadId) catch {};
            },
            CREATE_PROCESS_DEBUG_EVENT => {
                const create_process = debug_event.u.CreateProcessInfo;
                const dll_base = @intFromPtr(create_process.lpBaseOfImage);

                // Get process name from image
                var process_name: ?[]u8 = null;
                defer if (process_name) |name| allocator.free(name);

                if (create_process.lpImageName != null) {
                    const dll_name_address = memory.readProcessMemoryData(u64, process, @intFromPtr(create_process.lpImageName)) catch 0;

                    if (dll_name_address != 0) {
                        const is_wide = create_process.fUnicode != 0;
                        process_name = memory.readProcessMemoryString(allocator, process, dll_name_address, MAX_PATH, is_wide) catch null;
                    }
                }

                _ = process_info.addModule(allocator, dll_base, process_name, process) catch |err| {
                    print("Failed to add process module: {any}\n", .{err});
                };

                _ = process_info.addThread(debug_event.dwThreadId) catch {};

                if (process_name) |name| {
                    print("CreateProcess\nLoadDll: 0x{x:0>16} {s}\n", .{ dll_base, name });
                } else {
                    print("CreateProcess\nLoadDll: 0x{x:0>16}\n", .{dll_base});
                }
            },
            EXIT_THREAD_DEBUG_EVENT => {
                print("ExitThread\n", .{});
                process_info.removeThread(debug_event.dwThreadId);
            },
            EXIT_PROCESS_DEBUG_EVENT => print("ExitProcess\n", .{}),
            LOAD_DLL_DEBUG_EVENT => {
                const load_dll = debug_event.u.LoadDll;
                const dll_base = @intFromPtr(load_dll.lpBaseOfDll);

                var dll_name: ?[]u8 = null;
                defer if (dll_name) |name| allocator.free(name);

                if (load_dll.lpImageName != null) {
                    // Read the pointer to the name string
                    const dll_name_address = memory.readProcessMemoryData(u64, process, @intFromPtr(load_dll.lpImageName)) catch 0;

                    if (dll_name_address != 0) {
                        const is_wide = load_dll.fUnicode != 0;
                        dll_name = memory.readProcessMemoryString(allocator, process, dll_name_address, MAX_PATH, is_wide) catch null;
                    }
                }

                _ = process_info.addModule(allocator, dll_base, dll_name, process) catch |err| {
                    print("Failed to add module: {any}\n", .{err});
                };

                if (dll_name) |name| {
                    print("LoadDll: 0x{x:0>16} {s}\n", .{ dll_base, name });
                } else {
                    print("LoadDll: 0x{x:0>16}\n", .{dll_base});
                }
            },
            UNLOAD_DLL_DEBUG_EVENT => print("UnloadDll\n", .{}),
            OUTPUT_DEBUG_STRING_EVENT => {
                const debug_string_info = debug_event.u.DebugString;
                const is_wide = debug_string_info.fUnicode != 0;
                const address = @intFromPtr(debug_string_info.lpDebugStringData);
                const len = debug_string_info.nDebugStringLength;

                const debug_string = memory.readProcessMemoryString(allocator, process, address, len, is_wide) catch {
                    print("DebugOut: <failed to read string>\n", .{});
                    continue;
                };
                defer allocator.free(debug_string);

                print("DebugOut: {s}\n", .{debug_string});
            },
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

        // Check if a breakpoint was hit
        if (debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            const code = debug_event.u.Exception.ExceptionRecord.ExceptionCode;
            if (code == EXCEPTION_SINGLE_STEP) {
                if (breakpoints.wasBreakpointHit(ctx.context)) |bp_id| {
                    print("Breakpoint {} hit\n", .{bp_id});
                    continue_status = DBG_CONTINUE;
                }
            }
        }

        var continue_execution = false;

        while (!continue_execution) {
            // Try to resolve the instruction pointer to a symbol
            if (name_resolution.resolveAddressToName(allocator, ctx.context.Rip, &process_info)) |sym| {
                if (sym) |s| {
                    print("[0x{x:0>4}] {s}\n", .{ debug_event.dwThreadId, s });
                    allocator.free(s);
                } else {
                    print("[0x{x:0>4}]\n", .{debug_event.dwThreadId});
                }
            } else |_| {
                print("[0x{x:0>4}] 0x{x:0>16}\n", .{ debug_event.dwThreadId, ctx.context.Rip });
            }

            const cmd = command.readCommand(allocator, &process_info) catch |err| {
                print("Command parsing error: {any}\n", .{err});
                continue;
            };

            switch (cmd) {
                command.Command.StepInto => {
                    ctx.context.EFlags |= TRAP_FLAG;
                    const set_context_result = SetThreadContext(thread.getHandle(), &ctx.context);
                    if (set_context_result == 0) {
                        print("SetThreadContext failed\n", .{});
                        continue;
                    }
                    expect_step_exception = true;
                    continue_execution = true;
                },
                command.Command.Go => {
                    continue_execution = true;
                },
                command.Command.DisplayRegisters => {
                    registers.displayAllRegisters(ctx.context);
                },
                command.Command.DisplayBytes => |address| {
                    registers.displayBytes(process, address);
                },
                command.Command.ListNearest => |address| {
                    if (name_resolution.resolveAddressToName(allocator, address, &process_info)) |sym| {
                        if (sym) |s| {
                            print("{s}\n", .{s});
                            allocator.free(s);
                        } else {
                            print("No symbol found\n", .{});
                        }
                    } else |_| {
                        print("No symbol found\n", .{});
                    }
                },
                command.Command.Evaluate => |value| {
                    print(" = 0x{x}\n", .{value});
                },
                command.Command.SetBreakpoint => |address| {
                    breakpoints.addBreakpoint(address) catch |err| {
                        print("Failed to add breakpoint: {any}\n", .{err});
                    };
                },
                command.Command.ListBreakpoints => {
                    breakpoints.listBreakpoints(allocator, &process_info);
                },
                command.Command.ClearBreakpoint => |id| {
                    breakpoints.clearBreakpoint(id);
                },
                command.Command.CallStack => {
                    displayCallStack(allocator, &process_info, process, ctx.context);
                },
                command.Command.Quit => {
                    // The process will be terminated since we didn't detach
                    return;
                },
                command.Command.Unknown => {
                    // This shouldn't happen with our current implementation
                    continue;
                },
            }
        }

        if (debug_event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            break;
        }

        // Apply breakpoints before continuing
        breakpoints.applyBreakpoints(&process_info, debug_event.dwThreadId);

        _ = ContinueDebugEvent(
            debug_event.dwProcessId,
            debug_event.dwThreadId,
            continue_status,
        );
    }
}