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
const DR7_LEN_BIT = [_]u6{ 19, 23, 27, 31 };
const DR7_RW_BIT = [_]u6{ 17, 21, 25, 29 };
const DR7_LE_BIT = [_]u6{ 0, 2, 4, 6 };
const DR7_GE_BIT = [_]u6{ 1, 3, 5, 7 };

const DR7_LEN_SIZE: u6 = 2;
const DR7_RW_SIZE: u6 = 2;

const DR6_B_BIT = [_]u6{ 0, 1, 2, 3 };

const EFLAG_RF: u6 = 16;

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
        if (self.breakpoints.items.len == 0) {
            print("No breakpoints set\n", .{});
            return;
        }

        print("ID  Address            Status    Symbol\n", .{});
        print("--  ----------------   -------   ------\n", .{});

        for (self.breakpoints.items) |bp| {
            const status = if (bp.id < 4) "Active" else "Invalid";
            if (name_resolution.resolveAddressToName(self.allocator, bp.addr, proc)) |sym_opt| {
                if (sym_opt) |sym| {
                    print("{:2}  0x{X:0>16} {s:>7}   {s}\n", .{ bp.id, bp.addr, status, sym });
                    self.allocator.free(sym);
                } else {
                    print("{:2}  0x{X:0>16} {s:>7}\n", .{ bp.id, bp.addr, status });
                }
            } else |_| {
                print("{:2}  0x{X:0>16} {s:>7}\n", .{ bp.id, bp.addr, status });
            }
        }
        print("\n", .{});
    }

    pub fn clearBreakpointById(self: *BreakpointManager, id: u32) bool {
        var i: usize = 0;
        while (i < self.breakpoints.items.len) {
            if (self.breakpoints.items[i].id == id) {
                _ = self.breakpoints.orderedRemove(i);
                return true;
            }
            i += 1;
        }
        return false;
    }

    pub fn clearBreakpointByAddress(self: *BreakpointManager, addr: u64) bool {
        var i: usize = 0;
        while (i < self.breakpoints.items.len) {
            if (self.breakpoints.items[i].addr == addr) {
                _ = self.breakpoints.orderedRemove(i);
                return true;
            }
            i += 1;
        }
        return false;
    }

    pub fn findBreakpointByAddress(self: BreakpointManager, addr: u64) ?u32 {
        for (self.breakpoints.items) |bp| {
            if (bp.addr == addr) {
                return bp.id;
            }
        }
        return null;
    }

    pub fn wasBreakpointHit(self: BreakpointManager, thread_context: *const CONTEXT) ?u32 {
        for (0..self.breakpoints.items.len) |idx| {
            if (getBit(thread_context.Dr6, DR6_B_BIT[idx])) {
                // return @intCast(idx);
                return self.breakpoints.items[idx].id;
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
                    // Set LEN to 0 (1 byte), RW to 0 (execute), LE to 1 (enabled)
                    setBits(&ctx.context.Dr7, 0, DR7_LEN_BIT[idx], DR7_LEN_SIZE);
                    setBits(&ctx.context.Dr7, 0, DR7_RW_BIT[idx], DR7_RW_SIZE);
                    setBits(&ctx.context.Dr7, 1, DR7_LE_BIT[idx], 1);

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
                    setBits(&ctx.context.Dr7, 0, DR7_LE_BIT[idx], 1);
                    break;
                }
            }

            // Prevent current thread from hitting breakpoint on current instruction
            // Set resume flag for the thread that caused the break
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

// Bit manipulation helper functions
fn setBits(val: anytype, set_val: @TypeOf(val.*), start_bit: usize, bit_count: usize) void {
    const T = @TypeOf(val.*);
    const mask: T = (@as(T, 1) << @intCast(bit_count)) - 1;
    const shifted_mask = mask << @intCast(start_bit);
    val.* = (val.* & ~shifted_mask) | ((set_val & mask) << @intCast(start_bit));
}

fn getBit(val: u64, bit_pos: usize) bool {
    return (val & (@as(u64, 1) << @intCast(bit_pos))) != 0;
}
