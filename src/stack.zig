const std = @import("std");
const windows = std.os.windows;
const WINAPI = windows.WINAPI;
const print = std.debug.print;
const Allocator = std.mem.Allocator;

const util = @import("util.zig");
const memory = @import("memory.zig");
const process = @import("process.zig");

// Windows API types
const DWORD = windows.DWORD;
const CONTEXT = util.CONTEXT;

// Windows PE constants
const IMAGE_DIRECTORY_ENTRY_EXCEPTION: DWORD = 3;

// Runtime function structure for x64 stack unwinding
const RUNTIME_FUNCTION = packed struct {
    BeginAddress: u32,
    EndAddress: u32,
    UnwindInfo: u32,
};

// Unwind info header structure
const UNWIND_INFO = packed struct {
    version_flags: u8,
    size_of_prolog: u8,
    count_of_codes: u8,
    frame_register_offset: u8,
};

// Unwind code structure
const UNWIND_CODE = packed struct {
    code_offset: u8,
    unwind_op_info: u8,
};

// Unwind operation constants
const UWOP_PUSH_NONVOL: u8 = 0;
const UWOP_ALLOC_LARGE: u8 = 1;
const UWOP_ALLOC_SMALL: u8 = 2;
const UWOP_SET_FPREG: u8 = 3;
const UWOP_SAVE_NONVOL: u8 = 4;
const UWOP_SAVE_NONVOL_FAR: u8 = 5;
const UWOP_SAVE_XMM128: u8 = 8;
const UWOP_SAVE_XMM128_FAR: u8 = 9;
const UWOP_PUSH_MACHFRAME: u8 = 10;

// Unwind flags
const UNW_FLAG_NHANDLER: u8 = 0x0;
const UNW_FLAG_EHANDLER: u8 = 0x1;
const UNW_FLAG_UHANDLER: u8 = 0x2;
const UNW_FLAG_CHAININFO: u8 = 0x4;

// Logical unwind operations
const UnwindOp = union(enum) {
    PushNonVolatile: struct { reg: u8 },
    Alloc: struct { size: u32 },
    SetFpreg: struct { frame_register: u8, frame_offset: u16 },
    SaveNonVolatile: struct { reg: u8, offset: u32 },
    SaveXmm128: struct { reg: u8, offset: u32 },
    PushMachFrame: struct { error_code: bool },
};

// Unwind code with operation
const UnwindCode = struct {
    code_offset: u8,
    op: UnwindOp,

    pub fn deinit(self: *UnwindCode, allocator: Allocator) void {
        _ = self;
        _ = allocator;
        // Nothing to deallocate for now
    }
};

// Stack unwinding errors
pub const StackError = error{
    NoUnwindData,
    IncompleteUnwindCode,
    UnrecognizedUnwindOp,
    MemoryReadError,
    ChainedInfoNotImplemented,
};

// Find runtime function containing the given RVA
fn findRuntimeFunction(addr: u32, function_list: []const RUNTIME_FUNCTION) ?*const RUNTIME_FUNCTION {
    // Binary search for the function containing this address
    var left: usize = 0;
    var right: usize = function_list.len;

    while (left < right) {
        const mid = left + (right - left) / 2;
        const func = &function_list[mid];

        if (addr < func.BeginAddress) {
            right = mid;
        } else if (addr >= func.EndAddress) {
            left = mid + 1;
        } else {
            return func;
        }
    }

    // Check boundaries for inexact matches
    if (left > 0) {
        const func = &function_list[left - 1];
        if (func.BeginAddress <= addr and addr < func.EndAddress) {
            return func;
        }
    }

    return null;
}

// Split bitfield values (mimics the Rust macro)
fn splitBits2(comptime T: type, value: T, comptime size1: u8, comptime size2: u8) struct { u8, u8 } {
    const mask1 = (@as(T, 1) << size1) - 1;
    const field1 = @as(u8, @intCast(value & mask1));
    const field2 = @as(u8, @intCast((value >> size1) & ((@as(T, 1) << size2) - 1)));
    return .{ field1, field2 };
}

fn splitBits4(comptime T: type, value: T, comptime size1: u8, comptime size2: u8, comptime size3: u8, comptime size4: u8) struct { u8, u8, u8, u8 } {
    var temp_value = value;
    const field1 = @as(u8, @intCast(temp_value & ((@as(T, 1) << size1) - 1)));
    temp_value >>= size1;
    const field2 = @as(u8, @intCast(temp_value & ((@as(T, 1) << size2) - 1)));
    temp_value >>= size2;
    const field3 = @as(u8, @intCast(temp_value & ((@as(T, 1) << size3) - 1)));
    temp_value >>= size3;
    const field4 = @as(u8, @intCast(temp_value & ((@as(T, 1) << size4) - 1)));
    return .{ field1, field2, field3, field4 };
}

// Parse unwind operations from unwind codes
fn getUnwindOps(allocator: Allocator, code_slots: []const u16, frame_register: u8, frame_offset: u16) ![]UnwindCode {
    var ops = std.ArrayList(UnwindCode).init(allocator);
    defer ops.deinit();

    var i: usize = 0;
    while (i < code_slots.len) {
        const split = splitBits4(u16, code_slots[i], 8, 4, 4, 0);
        const code_offset = split[0];
        const unwind_op = split[1];
        const op_info = split[2];

        switch (unwind_op) {
            UWOP_PUSH_NONVOL => {
                try ops.append(UnwindCode{
                    .code_offset = code_offset,
                    .op = UnwindOp{ .PushNonVolatile = .{ .reg = op_info } },
                });
            },
            UWOP_ALLOC_LARGE => {
                if (op_info == 0) {
                    if (i + 1 >= code_slots.len) {
                        return StackError.IncompleteUnwindCode;
                    }
                    const size = @as(u32, code_slots[i + 1]) * 8;
                    try ops.append(UnwindCode{
                        .code_offset = code_offset,
                        .op = UnwindOp{ .Alloc = .{ .size = size } },
                    });
                    i += 1;
                } else if (op_info == 1) {
                    if (i + 2 >= code_slots.len) {
                        return StackError.IncompleteUnwindCode;
                    }
                    const size = @as(u32, code_slots[i + 1]) + (@as(u32, code_slots[i + 2]) << 16);
                    try ops.append(UnwindCode{
                        .code_offset = code_offset,
                        .op = UnwindOp{ .Alloc = .{ .size = size } },
                    });
                    i += 2;
                }
            },
            UWOP_ALLOC_SMALL => {
                const size = @as(u32, op_info) * 8 + 8;
                try ops.append(UnwindCode{
                    .code_offset = code_offset,
                    .op = UnwindOp{ .Alloc = .{ .size = size } },
                });
            },
            UWOP_SET_FPREG => {
                try ops.append(UnwindCode{
                    .code_offset = code_offset,
                    .op = UnwindOp{ .SetFpreg = .{ .frame_register = frame_register, .frame_offset = frame_offset } },
                });
            },
            UWOP_SAVE_NONVOL => {
                if (i + 1 >= code_slots.len) {
                    return StackError.IncompleteUnwindCode;
                }
                const offset = @as(u32, code_slots[i + 1]);
                try ops.append(UnwindCode{
                    .code_offset = code_offset,
                    .op = UnwindOp{ .SaveNonVolatile = .{ .reg = op_info, .offset = offset } },
                });
                i += 1;
            },
            UWOP_SAVE_NONVOL_FAR => {
                if (i + 2 >= code_slots.len) {
                    return StackError.IncompleteUnwindCode;
                }
                const offset = @as(u32, code_slots[i + 1]) + (@as(u32, code_slots[i + 2]) << 16);
                try ops.append(UnwindCode{
                    .code_offset = code_offset,
                    .op = UnwindOp{ .SaveNonVolatile = .{ .reg = op_info, .offset = offset } },
                });
                i += 2;
            },
            UWOP_SAVE_XMM128 => {
                if (i + 1 >= code_slots.len) {
                    return StackError.IncompleteUnwindCode;
                }
                const offset = @as(u32, code_slots[i + 1]);
                try ops.append(UnwindCode{
                    .code_offset = code_offset,
                    .op = UnwindOp{ .SaveXmm128 = .{ .reg = op_info, .offset = offset } },
                });
                i += 1;
            },
            UWOP_SAVE_XMM128_FAR => {
                if (i + 2 >= code_slots.len) {
                    return StackError.IncompleteUnwindCode;
                }
                const offset = @as(u32, code_slots[i + 1]) + (@as(u32, code_slots[i + 2]) << 16);
                try ops.append(UnwindCode{
                    .code_offset = code_offset,
                    .op = UnwindOp{ .SaveXmm128 = .{ .reg = op_info, .offset = offset } },
                });
                i += 2;
            },
            UWOP_PUSH_MACHFRAME => {
                try ops.append(UnwindCode{
                    .code_offset = code_offset,
                    .op = UnwindOp{ .PushMachFrame = .{ .error_code = op_info != 0 } },
                });
            },
            else => return StackError.UnrecognizedUnwindOp,
        }
        i += 1;
    }

    return ops.toOwnedSlice();
}

// Get register reference by register number
fn getOpRegister(context: *CONTEXT, reg: u8) *u64 {
    return switch (reg) {
        0 => &context.Rax,
        1 => &context.Rcx,
        2 => &context.Rdx,
        3 => &context.Rbx,
        4 => &context.Rsp,
        5 => &context.Rbp,
        6 => &context.Rsi,
        7 => &context.Rdi,
        8 => &context.R8,
        9 => &context.R9,
        10 => &context.R10,
        11 => &context.R11,
        12 => &context.R12,
        13 => &context.R13,
        14 => &context.R14,
        15 => &context.R15,
        else => unreachable,
    };
}

// Apply unwind operations to context
fn applyUnwindOps(allocator: Allocator, context: *const CONTEXT, unwind_ops: []const UnwindCode, func_address: u64, mem_source: memory.MemorySource) !?CONTEXT {
    var unwound_context = context.*;

    for (unwind_ops) |unwind| {
        const func_offset = unwound_context.Rip - func_address;
        if (unwind.code_offset <= func_offset) {
            switch (unwind.op) {
                .Alloc => |alloc| {
                    unwound_context.Rsp += alloc.size;
                },
                .PushNonVolatile => |push| {
                    const addr = unwound_context.Rsp;
                    const val = memory.readMemoryData(u64, mem_source, addr, allocator) catch return StackError.MemoryReadError;
                    getOpRegister(&unwound_context, push.reg).* = val;
                    unwound_context.Rsp += 8;
                },
                .SaveNonVolatile => |save| {
                    const addr = unwound_context.Rsp + save.offset;
                    const val = memory.readMemoryData(u64, mem_source, addr, allocator) catch return StackError.MemoryReadError;
                    getOpRegister(&unwound_context, save.reg).* = val;
                },
                .SetFpreg => |fpreg| {
                    unwound_context.Rsp = getOpRegister(&unwound_context, fpreg.frame_register).* - fpreg.frame_offset;
                },
                .PushMachFrame => |machframe| {
                    if (machframe.error_code) {
                        // Skip the error code on stack
                        unwound_context.Rsp += 8;
                    }
                    // The return address is already at RSP
                },
                else => {
                    // NYI: Other unwind operations
                    print("NYI: Unwind operation not yet implemented\n", .{});
                },
            }
        }
    }

    return unwound_context;
}

// Main stack unwinding function
pub fn unwindContext(allocator: Allocator, proc: *process.Process, context: CONTEXT, mem_source: memory.MemorySource) !?CONTEXT {
    const module_opt = proc.getContainingModule(context.Rip);
    if (module_opt) |mod| {
        // Get exception data directory
        const data_directory = mod.getDataDirectory(IMAGE_DIRECTORY_ENTRY_EXCEPTION);

        if (data_directory.VirtualAddress != 0 and data_directory.Size != 0) {
            const count = data_directory.Size / @sizeOf(RUNTIME_FUNCTION);
            const table_address = mod.address + data_directory.VirtualAddress;

            // Read runtime function table
            var functions = std.ArrayList(RUNTIME_FUNCTION).init(allocator);
            defer functions.deinit();
            try functions.resize(count);

            const table_bytes = try mem_source.readRawMemory(table_address, functions.items.len * @sizeOf(RUNTIME_FUNCTION), allocator);
            defer allocator.free(table_bytes);
            @memcpy(std.mem.sliceAsBytes(functions.items), table_bytes);

            const rva = @as(u32, @intCast(context.Rip - mod.address));
            const func_opt = findRuntimeFunction(rva, functions.items);

            if (func_opt) |func| {
                // We have unwind data
                const info_addr = mod.address + func.UnwindInfo;
                const info = memory.readMemoryData(UNWIND_INFO, mem_source, info_addr, allocator) catch return StackError.MemoryReadError;

                const split = splitBits2(u8, info.version_flags, 3, 5);
                const flags = split[1];

                if (flags & UNW_FLAG_CHAININFO == UNW_FLAG_CHAININFO) {
                    return StackError.ChainedInfoNotImplemented;
                }

                const reg_split = splitBits2(u8, info.frame_register_offset, 4, 4);
                const frame_register = reg_split[0];
                const frame_offset = @as(u16, reg_split[1]) * 16;

                // Read unwind codes
                const codes_size = info.count_of_codes;
                var codes = std.ArrayList(u16).init(allocator);
                defer codes.deinit();
                try codes.resize(codes_size);

                const codes_bytes = try mem_source.readRawMemory(info_addr + 4, codes.items.len * @sizeOf(u16), allocator);
                defer allocator.free(codes_bytes);
                @memcpy(std.mem.sliceAsBytes(codes.items), codes_bytes);

                // Parse unwind operations
                const unwind_ops = try getUnwindOps(allocator, codes.items, frame_register, frame_offset);
                defer allocator.free(unwind_ops);

                if (try applyUnwindOps(allocator, &context, unwind_ops, mod.address + func.BeginAddress, mem_source)) |unwound_ctx| {
                    var ctx = unwound_ctx;

                    // Read return address from stack
                    ctx.Rip = memory.readMemoryData(u64, mem_source, ctx.Rsp, allocator) catch return StackError.MemoryReadError;
                    ctx.Rsp += 8;

                    // Check for end of stack
                    if (ctx.Rip == 0) {
                        return null;
                    }

                    return ctx;
                }

                return null;
            } else {
                // Leaf function: return address is at [RSP]
                var ctx = context;
                ctx.Rip = memory.readMemoryData(u64, mem_source, ctx.Rsp, allocator) catch return StackError.MemoryReadError;
                ctx.Rsp += 8;
                return ctx;
            }
        }
    }

    return null;
}

// Walk the entire stack and print stack frames
pub fn walkStack(allocator: Allocator, proc: *process.Process, context: CONTEXT, mem_source: memory.MemorySource) !void {
    var current_context = context;
    var frame_count: u32 = 0;

    print("Call stack:\n", .{});

    while (frame_count < 100) { // Limit to prevent infinite loops
        // Print current frame
        const module_name = if (proc.getContainingModule(current_context.Rip)) |mod| mod.name else "Unknown";
        print("{:3} {X:0>16} {s}\n", .{ frame_count, current_context.Rip, module_name });

        // Try to unwind to the next frame
        if (try unwindContext(allocator, proc, current_context, mem_source)) |next_context| {
            current_context = next_context;
            frame_count += 1;
        } else {
            break;
        }
    }
}
