const std = @import("std");
const windows = std.os.windows;
const WINAPI = windows.WINAPI;
const print = std.debug.print;

const util = @import("util.zig");
const memory = @import("memory.zig");
const process = @import("process.zig");
const name_resolution = @import("name_resolution.zig");

// Windows API types and functions
const HANDLE = windows.HANDLE;
const DWORD = windows.DWORD;
const BOOL = windows.BOOL;
const CONTEXT = util.CONTEXT;
const AlignedContext = util.AlignedContext;
const AutoClosedHandle = util.AutoClosedHandle;

const FALSE: BOOL = 0;
const THREAD_GET_CONTEXT: DWORD = 0x0008;
const THREAD_SET_CONTEXT: DWORD = 0x0010;

extern "kernel32" fn OpenThread(
    dwDesiredAccess: DWORD,
    bInheritHandle: BOOL,
    dwThreadId: DWORD,
) callconv(WINAPI) HANDLE;

extern "kernel32" fn GetThreadContext(
    hThread: HANDLE,
    lpContext: *CONTEXT,
) callconv(WINAPI) BOOL;

extern "kernel32" fn SetThreadContext(
    hThread: HANDLE,
    lpContext: *const CONTEXT,
) callconv(WINAPI) BOOL;

// Debug register bit positions and sizes
const DR7_LEN_BIT = [_]usize{ 19, 23, 27, 31 };
const DR7_RW_BIT = [_]usize{ 17, 21, 25, 29 };
const DR7_LE_BIT = [_]usize{ 0, 2, 4, 6 };
const DR7_GE_BIT = [_]usize{ 1, 3, 5, 7 };

const DR7_LEN_SIZE: usize = 2;
const DR7_RW_SIZE: usize = 2;

const DR6_B_BIT = [_]usize{ 0, 1, 2, 3 };

const EFLAG_RF: usize = 16;

const Breakpoint = struct {
    addr: u64,
    id: u32,
};

pub const BreakpointManager = struct {
    breakpoints: std.ArrayList(Breakpoint),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) BreakpointManager {
        return BreakpointManager{
            .breakpoints = std.ArrayList(Breakpoint).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *BreakpointManager) void {
        self.breakpoints.deinit();
    }

    fn getFreeId(self: BreakpointManager) !u32 {
        for (0..4) |i| {
            const id = @as(u32, @intCast(i));
            var found = false;
            for (self.breakpoints.items) |bp| {
                if (bp.id == id) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                return id;
            }
        }
        return error.TooManyBreakpoints;
    }

    pub fn addBreakpoint(self: *BreakpointManager, addr: u64) !void {
        const id = try self.getFreeId();
        try self.breakpoints.append(Breakpoint{ .addr = addr, .id = id });

        // Sort by ID
        std.mem.sort(Breakpoint, self.breakpoints.items, {}, struct {
            fn lessThan(_: void, a: Breakpoint, b: Breakpoint) bool {
                return a.id < b.id;
            }
        }.lessThan);
    }

    pub fn listBreakpoints(self: BreakpointManager, proc: *process.Process) void {
        for (self.breakpoints.items) |bp| {
            if (name_resolution.resolveAddressToName(self.allocator, bp.addr, proc)) |sym_opt| {
                if (sym_opt) |sym| {
                    print("{:3} {X:0>18} ({})\n", .{ bp.id, bp.addr, sym });
                    self.allocator.free(sym);
                } else {
                    print("{:3} {X:0>18}\n", .{ bp.id, bp.addr });
                }
            } else |_| {
                print("{:3} {X:0>18}\n", .{ bp.id, bp.addr });
            }
        }
    }

    pub fn clearBreakpoint(self: *BreakpointManager, id: u32) void {
        var i: usize = 0;
        while (i < self.breakpoints.items.len) {
            if (self.breakpoints.items[i].id == id) {
                _ = self.breakpoints.orderedRemove(i);
                return;
            }
            i += 1;
        }
    }

    pub fn wasBreakpointHit(self: BreakpointManager, thread_context: *const CONTEXT) ?u32 {
        for (0..self.breakpoints.items.len) |idx| {
            if (getBit(thread_context.Dr6, DR6_B_BIT[idx])) {
                return @intCast(idx);
            }
        }
        return null;
    }

    pub fn applyBreakpoints(self: *BreakpointManager, proc: *process.Process, resume_thread_id: u32, mem_source: memory.MemorySource) void {
        _ = mem_source; // Currently unused

        const threads = proc.iterateThreads();
        for (threads) |thread_id| {
            var ctx: AlignedContext = std.mem.zeroes(AlignedContext);
            ctx.context.ContextFlags = util.CONTEXT_ALL;

            var thread_handle = AutoClosedHandle.init(OpenThread(
                THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                FALSE,
                thread_id,
            ));
            defer thread_handle.deinit();

            const ret = GetThreadContext(thread_handle.get(), &ctx.context);
            if (ret == 0) {
                print("Could not get thread context of thread {X}\n", .{thread_id});
                continue;
            }

            // Hardware breakpoints are limited to 4
            for (0..4) |idx| {
                if (self.breakpoints.items.len > idx) {
                    setBits(&ctx.context.Dr7, 0, DR7_LEN_BIT[idx], DR7_LEN_SIZE);
                    setBits(&ctx.context.Dr7, 0, DR7_RW_BIT[idx], DR7_RW_SIZE);
                    setBits(&ctx.context.Dr7, 1, DR7_LE_BIT[idx], 1);

                    switch (idx) {
                        0 => ctx.context.Dr0 = self.breakpoints.items[idx].addr,
                        1 => ctx.context.Dr1 = self.breakpoints.items[idx].addr,
                        2 => ctx.context.Dr2 = self.breakpoints.items[idx].addr,
                        3 => ctx.context.Dr3 = self.breakpoints.items[idx].addr,
                        else => {},
                    }
                } else {
                    // Disable unused breakpoint slots
                    setBits(&ctx.context.Dr7, 0, DR7_LE_BIT[idx], 1);
                    break;
                }
            }

            // Prevent current thread from hitting breakpoint on current instruction
            if (thread_id == resume_thread_id) {
                setBits(&ctx.context.EFlags, 1, EFLAG_RF, 1);
            }

            const set_ret = SetThreadContext(thread_handle.get(), &ctx.context);
            if (set_ret == 0) {
                print("Could not set thread context of thread {X}\n", .{thread_id});
            }
        }
    }
};

// Bit manipulation helper functions - matches the Rust implementation exactly
fn setBits(val: anytype, set_val: @TypeOf(val.*), start_bit: usize, bit_count: usize) void {
    const T = @TypeOf(val.*);
    const max_bits = @sizeOf(T) * 8;

    // First, mask out the relevant bits
    var mask: T = std.math.maxInt(T) << @intCast(max_bits - bit_count);
    mask = mask >> @intCast(max_bits - 1 - start_bit);
    const inv_mask = ~mask;

    val.* = val.* & inv_mask;
    val.* = val.* | (set_val << @intCast(start_bit + 1 - bit_count));
}

fn getBit(val: anytype, bit_index: usize) bool {
    const T = @TypeOf(val);
    const mask: T = @as(T, 1) << @intCast(bit_index);
    const masked_val = val & mask;
    return masked_val != 0;
}
