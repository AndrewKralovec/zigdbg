const std = @import("std");
const windows = std.os.windows;
const print = std.debug.print;

const memory = @import("memory.zig");

// Display all registers
pub fn displayAllRegisters(context: windows.CONTEXT) void {
    print("rax=0x{x:0>16} rbx=0x{x:0>16} rcx=0x{x:0>16}\n", .{ context.Rax, context.Rbx, context.Rcx });
    print("rdx=0x{x:0>16} rsi=0x{x:0>16} rdi=0x{x:0>16}\n", .{ context.Rdx, context.Rsi, context.Rdi });
    print("rip=0x{x:0>16} rsp=0x{x:0>16} rbp=0x{x:0>16}\n", .{ context.Rip, context.Rsp, context.Rbp });
    print(" r8=0x{x:0>16}  r9=0x{x:0>16} r10=0x{x:0>16}\n", .{ context.R8, context.R9, context.R10 });
    print("r11=0x{x:0>16} r12=0x{x:0>16} r13=0x{x:0>16}\n", .{ context.R11, context.R12, context.R13 });
    print("r14=0x{x:0>16} r15=0x{x:0>16} eflags=0x{x:0>8}\n", .{ context.R14, context.R15, context.EFlags });
}

// Display bytes at a memory address
pub fn displayBytes(process: windows.HANDLE, address: u64) void {
    var buffer: [16]u8 = undefined;
    const bytes_read = memory.readProcessMemoryBytes(process, address, &buffer) catch |err| {
        print("ReadProcessMemory failed: {any}\n", .{err});
        return;
    };

    print("{x:0>8}: ", .{@as(u32, @truncate(address))});
    for (0..bytes_read) |i| {
        print("{x:0>2} ", .{buffer[i]});
    }
    print("\n", .{});
}