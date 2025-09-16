const std = @import("std");
const windows = std.os.windows;
const print = std.debug.print;
const Allocator = std.mem.Allocator;

const memory = @import("memory.zig");
const Process = @import("process.zig").Process;

const IMAGE_DOS_HEADER = @import("module.zig").IMAGE_DOS_HEADER;
const IMAGE_NT_HEADERS64 = @import("module.zig").IMAGE_NT_HEADERS64;

// Exception directory entry index
const IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3;

// PE constants
const IMAGE_DOS_SIGNATURE = 0x5A4D; // MZ
const IMAGE_NT_SIGNATURE = 0x00004550; // PE00

// Stack unwinding structures
pub const RUNTIME_FUNCTION = extern struct {
    BeginAddress: u32,
    EndAddress: u32,
    UnwindInfo: u32,
};

pub const UNWIND_INFO = extern struct {
    version_flags: u8,
    size_of_prolog: u8,
    count_of_codes: u8,
    frame_register_offset: u8,
};

pub const UNWIND_CODE = extern struct {
    offset_in_prolog: u8,
    unwind_op_info: u8,
};

// Unwind operation codes
const UWOP_PUSH_NONVOL = 0;
const UWOP_ALLOC_LARGE = 1;
const UWOP_ALLOC_SMALL = 2;
const UWOP_SET_FPREG = 3;
const UWOP_SAVE_NONVOL = 4;
const UWOP_SAVE_NONVOL_FAR = 5;
const UWOP_SAVE_XMM128 = 8;
const UWOP_SAVE_XMM128_FAR = 9;
const UWOP_PUSH_MACHFRAME = 10;

// Stack frame structure for call stack
pub const StackFrame = struct {
    rip: u64,
    rsp: u64,
    rbp: u64,

    const Self = @This();
};

// Stack unwinding functions
pub fn findRuntimeFunction(process_info: *Process, process: windows.HANDLE, rip: u64) ?RUNTIME_FUNCTION {
    const module = process_info.getContainingModule(rip) orelse {
        return null;
    };

    // Read exception directory from PE headers
    const dos_header = memory.readProcessMemoryData(IMAGE_DOS_HEADER, process, module.base_address) catch |err| {
        print("Failed to read DOS header: {any}\n", .{err});
        return null;
    };
    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) return null;

    const pe_header_addr = module.base_address + @as(u64, @intCast(dos_header.e_lfanew));
    const pe_header = memory.readProcessMemoryData(IMAGE_NT_HEADERS64, process, pe_header_addr) catch |err| {
        print("Failed to read PE header: {any}\n", .{err});
        return null;
    };
    if (pe_header.Signature != IMAGE_NT_SIGNATURE) return null;

    const exception_dir = pe_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (exception_dir.VirtualAddress == 0) {
        return null;
    }

    const exception_table_addr = module.base_address + exception_dir.VirtualAddress;
    const num_functions = exception_dir.Size / @sizeOf(RUNTIME_FUNCTION);

    // Binary search through runtime functions
    var left: u32 = 0;
    var right: u32 = num_functions;

    while (left < right) {
        const mid = left + (right - left) / 2;
        const func_addr = exception_table_addr + (mid * @sizeOf(RUNTIME_FUNCTION));

        const runtime_func = memory.readProcessMemoryData(RUNTIME_FUNCTION, process, func_addr) catch |err| {
            print("Failed to read RUNTIME_FUNCTION: {any}\n", .{err});
            return null;
        };
        const func_start = module.base_address + runtime_func.BeginAddress;
        const func_end = module.base_address + runtime_func.EndAddress;

        if (rip >= func_start and rip < func_end) {
            return runtime_func;
        } else if (rip < func_start) {
            right = mid;
        } else {
            left = mid + 1;
        }
    }

    return null;
}

pub fn unwindContext(allocator: Allocator, process_info: *Process, process: windows.HANDLE, context: windows.CONTEXT) ?windows.CONTEXT {
    const runtime_func = findRuntimeFunction(process_info, process, context.Rip) orelse {
        return null;
    };
    const module = process_info.getContainingModule(context.Rip) orelse {
        return null;
    };

    // Read unwind info
    const unwind_info_addr = module.base_address + runtime_func.UnwindInfo;
    const unwind_info = memory.readProcessMemoryData(UNWIND_INFO, process, unwind_info_addr) catch {
        return null;
    };

    // Create a new context for unwinding
    var new_context = context;

    // Read unwind codes
    const codes_addr = unwind_info_addr + @sizeOf(UNWIND_INFO);
    const codes = memory.readProcessMemoryArray(UNWIND_CODE, allocator, process, codes_addr, unwind_info.count_of_codes) catch {
        return null;
    };
    defer allocator.free(codes);

    // Process unwind codes in reverse order
    var i = codes.len;
    while (i > 0) {
        i -= 1;
        const code = codes[i];
        const unwind_op = code.unwind_op_info & 0x0F;
        const op_info = (code.unwind_op_info & 0xF0) >> 4;

        switch (unwind_op) {
            UWOP_PUSH_NONVOL => {
                // Pop register from stack
                const reg_value = memory.readProcessMemoryData(u64, process, new_context.Rsp) catch return null;
                new_context.Rsp += 8;

                // Restore the register based on op_info
                switch (op_info) {
                    0 => new_context.Rax = reg_value,
                    1 => new_context.Rcx = reg_value,
                    2 => new_context.Rdx = reg_value,
                    3 => new_context.Rbx = reg_value,
                    5 => new_context.Rbp = reg_value,
                    6 => new_context.Rsi = reg_value,
                    7 => new_context.Rdi = reg_value,
                    8 => new_context.R8 = reg_value,
                    9 => new_context.R9 = reg_value,
                    10 => new_context.R10 = reg_value,
                    11 => new_context.R11 = reg_value,
                    12 => new_context.R12 = reg_value,
                    13 => new_context.R13 = reg_value,
                    14 => new_context.R14 = reg_value,
                    15 => new_context.R15 = reg_value,
                    else => {},
                }
            },
            UWOP_ALLOC_LARGE => {
                // Large stack allocation
                if (op_info == 0) {
                    // Size is in next slot * 8
                    if (i > 0) {
                        i -= 1;
                        const size_code = codes[i];
                        const alloc_size = (@as(u64, size_code.unwind_op_info) << 8) | size_code.offset_in_prolog;
                        new_context.Rsp += alloc_size * 8;
                    }
                } else {
                    // Size is in next two slots
                    if (i > 1) {
                        i -= 1;
                        const low_code = codes[i];
                        i -= 1;
                        const high_code = codes[i];
                        const alloc_size = (@as(u64, high_code.unwind_op_info) << 24) |
                            (@as(u64, high_code.offset_in_prolog) << 16) |
                            (@as(u64, low_code.unwind_op_info) << 8) |
                            low_code.offset_in_prolog;
                        new_context.Rsp += alloc_size;
                    }
                }
            },
            UWOP_ALLOC_SMALL => {
                // Small stack allocation
                const alloc_size = (@as(u64, op_info) * 8) + 8;
                new_context.Rsp += alloc_size;
            },
            UWOP_SET_FPREG => {
                // Frame pointer was set
                const frame_offset = (@as(u64, @intCast(unwind_info.frame_register_offset & 0x0F))) * 16;
                new_context.Rsp = new_context.Rbp - frame_offset;
            },
            UWOP_SAVE_NONVOL => {
                // Restore non-volatile register from stack
                if (i > 0) {
                    i -= 1;
                    const offset_code = codes[i];
                    const offset = (@as(u64, offset_code.unwind_op_info) << 8) | offset_code.offset_in_prolog;
                    const saved_address = new_context.Rsp + (offset * 8);
                    const reg_value = memory.readProcessMemoryData(u64, process, saved_address) catch continue;

                    // Restore the register based on op_info
                    switch (op_info) {
                        0 => new_context.Rax = reg_value,
                        1 => new_context.Rcx = reg_value,
                        2 => new_context.Rdx = reg_value,
                        3 => new_context.Rbx = reg_value,
                        5 => new_context.Rbp = reg_value,
                        6 => new_context.Rsi = reg_value,
                        7 => new_context.Rdi = reg_value,
                        8 => new_context.R8 = reg_value,
                        9 => new_context.R9 = reg_value,
                        10 => new_context.R10 = reg_value,
                        11 => new_context.R11 = reg_value,
                        12 => new_context.R12 = reg_value,
                        13 => new_context.R13 = reg_value,
                        14 => new_context.R14 = reg_value,
                        15 => new_context.R15 = reg_value,
                        else => {},
                    }
                }
            },
            UWOP_SAVE_NONVOL_FAR => {
                // Restore non-volatile register from stack (far offset)
                if (i > 1) {
                    i -= 1;
                    const low_code = codes[i];
                    i -= 1;
                    const high_code = codes[i];
                    const offset = (@as(u64, high_code.unwind_op_info) << 24) |
                        (@as(u64, high_code.offset_in_prolog) << 16) |
                        (@as(u64, low_code.unwind_op_info) << 8) |
                        low_code.offset_in_prolog;
                    const saved_address = new_context.Rsp + offset;
                    const reg_value = memory.readProcessMemoryData(u64, process, saved_address) catch continue;

                    // Restore the register based on op_info
                    switch (op_info) {
                        0 => new_context.Rax = reg_value,
                        1 => new_context.Rcx = reg_value,
                        2 => new_context.Rdx = reg_value,
                        3 => new_context.Rbx = reg_value,
                        5 => new_context.Rbp = reg_value,
                        6 => new_context.Rsi = reg_value,
                        7 => new_context.Rdi = reg_value,
                        8 => new_context.R8 = reg_value,
                        9 => new_context.R9 = reg_value,
                        10 => new_context.R10 = reg_value,
                        11 => new_context.R11 = reg_value,
                        12 => new_context.R12 = reg_value,
                        13 => new_context.R13 = reg_value,
                        14 => new_context.R14 = reg_value,
                        15 => new_context.R15 = reg_value,
                        else => {},
                    }
                }
            },
            UWOP_SAVE_XMM128 => {
                // Skip XMM register saves for basic stack walking
                // XMM registers don't affect call stack unwinding
                if (i > 0) {
                    i -= 1; // Skip the offset slot
                }
            },
            UWOP_SAVE_XMM128_FAR => {
                // Skip XMM register saves for basic stack walking
                // XMM registers don't affect call stack unwinding
                if (i > 1) {
                    i -= 2; // Skip the two offset slots
                }
            },
            UWOP_PUSH_MACHFRAME => {
                // Machine frame push - adjust stack for hardware frame
                if (op_info == 0) {
                    // No error code - 5 slots: SS, RSP, EFLAGS, CS, RIP
                    new_context.Rsp += 5 * 8;
                } else {
                    // With error code - 6 slots: SS, RSP, EFLAGS, CS, RIP, ErrorCode
                    new_context.Rsp += 6 * 8;
                }
            },
            else => {
                print("unsupported frame {any} {any}\n", .{ unwind_op, unwind_info });
                // Skip unsupported unwind operations for now
            },
        }
    }

    // Get return address from stack
    const return_addr = memory.readProcessMemoryData(u64, process, new_context.Rsp) catch |err| {
        // If structured unwinding fails, fall back to frame pointer method
        if (context.Rbp != 0 and context.Rbp > context.Rsp) {
            // Try to read the saved frame pointer and return address
            const frame_data = memory.readProcessMemoryArray(u64, allocator, process, context.Rbp, 2) catch |frame_err| {
                print("Debug: Both structured and frame pointer unwinding failed: {any}, {any}\n", .{ err, frame_err });
                return null;
            };
            defer allocator.free(frame_data);

            if (frame_data.len >= 2 and frame_data[1] != 0) {
                new_context.Rbp = frame_data[0];
                new_context.Rip = frame_data[1];
                new_context.Rsp = context.Rbp + 16; // Skip saved RBP and return address
                return new_context;
            }
        }
        print("Debug: Failed to read return address from stack at 0x{x}: {any}\n", .{ new_context.Rsp, err });
        return null;
    };
    new_context.Rip = return_addr;
    new_context.Rsp += 8; // Pop return address

    return new_context;
}
