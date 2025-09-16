const std = @import("std");
const windows = std.os.windows;
const print = std.debug.print;
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;

const memory = @import("./memory.zig");
const util = @import("./util.zig");
const name_resolution = @import("name_resolution.zig");

// Thread access rights
const THREAD_GET_CONTEXT = 0x0008;
const THREAD_SET_CONTEXT = 0x0010;
const FALSE = windows.FALSE;

// Context flags for x64
const CONTEXT_AMD64 = 0x00100000;
const CONTEXT_CONTROL = CONTEXT_AMD64 | 0x00000001;
const CONTEXT_INTEGER = CONTEXT_AMD64 | 0x00000002;
const CONTEXT_SEGMENTS = CONTEXT_AMD64 | 0x00000004;
const CONTEXT_FLOATING_POINT = CONTEXT_AMD64 | 0x00000008;
const CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x00000010;
const CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS;

// Resume flag for hardware breakpoints
const EFLAG_RF = 16; // Bit position for Resume Flag in EFlags

// Debug register constants
const DR6_B_BIT = [4]usize{ 0, 1, 2, 3 }; // B0-B3 bits in DR6
const DR7_LE_BIT = [4]usize{ 0, 2, 4, 6 }; // Local Enable bits in DR7
const DR7_LEN_BIT = [4]usize{ 18, 22, 26, 30 }; // Length bits in DR7
const DR7_LEN_SIZE = 2;
const DR7_RW_BIT = [4]usize{ 16, 20, 24, 28 }; // Read/Write bits in DR7
const DR7_RW_SIZE = 2;

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

extern "kernel32" fn CloseHandle(hObject: windows.HANDLE) callconv(windows.WINAPI) windows.BOOL;

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

// Breakpoint structure
pub const Breakpoint = struct {
    addr: u64,
    id: u32,

    const Self = @This();
};

// Breakpoint manager
pub const BreakpointManager = struct {
    breakpoints: ArrayList(Breakpoint),
    next_id: u32,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .breakpoints = ArrayList(Breakpoint).init(allocator),
            .next_id = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        self.breakpoints.deinit();
    }

    pub fn addBreakpoint(self: *Self, addr: u64) !void {
        // Check if we already have 4 breakpoints (hardware limit)
        if (self.breakpoints.items.len >= 4) {
            print("Maximum of 4 hardware breakpoints supported\n", .{});
            return;
        }

        const breakpoint = Breakpoint{
            .addr = addr,
            .id = self.next_id,
        };

        try self.breakpoints.append(breakpoint);
        self.next_id += 1;

        // Sort by ID
        std.mem.sort(Breakpoint, self.breakpoints.items, {}, struct {
            fn lessThan(_: void, lhs: Breakpoint, rhs: Breakpoint) bool {
                return lhs.id < rhs.id;
            }
        }.lessThan);

        print("Breakpoint {} set at 0x{x}\n", .{ breakpoint.id, addr });
    }

    pub fn listBreakpoints(self: *const Self, allocator: Allocator, process_info: anytype) void {
        if (self.breakpoints.items.len == 0) {
            print("No breakpoints set\n", .{});
            return;
        }

        for (self.breakpoints.items) |bp| {
            if (name_resolution.resolveAddressToName(allocator, bp.addr, process_info)) |sym| {
                if (sym) |s| {
                    print("{:3} 0x{x:0>16} ({s})\n", .{ bp.id, bp.addr, s });
                    allocator.free(s);
                } else {
                    print("{:3} 0x{x:0>16}\n", .{ bp.id, bp.addr });
                }
            } else |_| {
                print("{:3} 0x{x:0>16}\n", .{ bp.id, bp.addr });
            }
        }
    }

    pub fn clearBreakpoint(self: *Self, id: u32) void {
        var i: usize = 0;
        while (i < self.breakpoints.items.len) {
            if (self.breakpoints.items[i].id == id) {
                _ = self.breakpoints.orderedRemove(i);
                print("Breakpoint {} cleared\n", .{id});
                return;
            }
            i += 1;
        }
        print("Breakpoint {} not found\n", .{id});
    }

    pub fn wasBreakpointHit(self: *const Self, context: windows.CONTEXT) ?u32 {
        for (self.breakpoints.items, 0..) |_, idx| {
            if (util.getBit(context.Dr6, DR6_B_BIT[idx])) {
                return self.breakpoints.items[idx].id;
            }
        }
        return null;
    }

    pub fn applyBreakpoints(self: *Self, process_info: anytype, resume_thread_id: u32) void {
        // Apply breakpoints to all threads
        for (process_info.thread_ids.items) |thread_id| {
            var thread = AutoClosedHandle.init(OpenThread(
                THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                FALSE,
                thread_id,
            ));
            defer thread.deinit();

            if (thread.getHandle() == windows.INVALID_HANDLE_VALUE) {
                continue;
            }

            var ctx = AlignedContext.init();
            ctx.context.ContextFlags = CONTEXT_ALL;

            const get_result = GetThreadContext(thread.getHandle(), &ctx.context);
            if (get_result == 0) {
                continue;
            }

            // Set resume flag for the thread that caused the break
            if (thread_id == resume_thread_id) {
                util.setBits(&ctx.context.EFlags, 1, EFLAG_RF, 1);
            }

            // Apply breakpoints to debug registers
            for (0..4) |idx| {
                if (self.breakpoints.items.len > idx) {
                    // Set LEN to 0 (1 byte), RW to 0 (execute), LE to 1 (enabled)
                    util.setBits(&ctx.context.Dr7, 0, DR7_LEN_BIT[idx], DR7_LEN_SIZE);
                    util.setBits(&ctx.context.Dr7, 0, DR7_RW_BIT[idx], DR7_RW_SIZE);
                    util.setBits(&ctx.context.Dr7, 1, DR7_LE_BIT[idx], 1);

                    // Set the breakpoint address
                    switch (idx) {
                        0 => ctx.context.Dr0 = self.breakpoints.items[idx].addr,
                        1 => ctx.context.Dr1 = self.breakpoints.items[idx].addr,
                        2 => ctx.context.Dr2 = self.breakpoints.items[idx].addr,
                        3 => ctx.context.Dr3 = self.breakpoints.items[idx].addr,
                        else => {},
                    }
                } else {
                    // Disable unused breakpoints
                    util.setBits(&ctx.context.Dr7, 0, DR7_LE_BIT[idx], 1);
                }
            }

            _ = SetThreadContext(thread.getHandle(), &ctx.context);
        }
    }
};
