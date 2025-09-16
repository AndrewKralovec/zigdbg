const std = @import("std");
const Allocator = std.mem.Allocator;
const print = std.debug.print;

const process_mod = @import("process.zig");

// Resolve symbol name to address
pub fn resolveNameToAddress(sym: []const u8, process: *process_mod.Process) !u64 {
    if (std.mem.indexOf(u8, sym, "!")) |pos| {
        // Fully qualified name: module!function
        const module_name = sym[0..pos];
        const func_name = sym[pos + 1 ..];

        if (process.getModuleByName(module_name)) |module| {
            if (module.findExportByName(func_name)) |addr| {
                return addr;
            } else {
                return error.FunctionNotFound;
            }
        } else {
            return error.ModuleNotFound;
        }
    } else {
        // Search all modules (not implemented for now)
        return error.NotImplemented;
    }
}

// Resolve address to symbol name
pub fn resolveAddressToName(allocator: Allocator, address: u64, process_info: *process_mod.Process) !?[]u8 {
    const module = process_info.getContainingModule(address) orelse return null;

    var closest_export: ?*process_mod.Export = null;
    var closest_addr: u64 = 0;

    // Find the closest export that comes before the address
    // This could be faster if we were always in sorted order
    for (module.exports.items) |*exp| {
        // print("\nexp: {?s} {any}\n", .{ exp.name, exp.target });
        switch (exp.target) {
            .RVA => |export_addr| {
                if (export_addr <= address) {
                    if (closest_export == null or closest_addr < export_addr) {
                        closest_export = exp;
                        closest_addr = export_addr;
                    }
                }
            },
            .Forwarder => {
                // Skip forwarders for now
            },
        }
    }

    if (closest_export) |exp| {
        const offset = address - closest_addr;
        const export_name = try exp.toString(allocator);
        defer allocator.free(export_name);

        if (offset == 0) {
            return try std.fmt.allocPrint(allocator, "{s}!{s}", .{ module.name, export_name });
        } else {
            return try std.fmt.allocPrint(allocator, "{s}!{s}+0x{x}", .{ module.name, export_name, offset });
        }
    }

    return null;
}
