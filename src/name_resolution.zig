const std = @import("std");
const Process = @import("./process.zig").Process;
const Module = @import("./module.zig").Module;
const Export = @import("./module.zig").Export;
const ExportTarget = @import("./module.zig").ExportTarget;

const AddressMatch = union(enum) {
    none,
    export_match: *const Export,
    public: []const u8,

    pub fn isNone(self: AddressMatch) bool {
        return switch (self) {
            .none => true,
            else => false,
        };
    }
};

// Resolve symbol name to address
pub fn resolveNameToAddress(sym: []const u8, process: *Process) !u64 {
    // Look for module separator '!'
    if (std.mem.indexOf(u8, sym, "!")) |pos| {
        const module_name = sym[0..pos];
        const func_name = sym[pos + 1 ..];

        if (process.getModuleByNameMut(module_name)) |module| {
            if (resolveFunctionInModule(module, func_name)) |addr| {
                return addr;
            } else {
                return error.FunctionNotFound; // Could not find {func_name} in module {module_name}
            }
        } else {
            return error.ModuleNotFound; // Could not find module {module_name}
        }
    } else {
        // Search all modules - not yet implemented
        return error.NotImplemented;
    }
}

pub fn resolveFunctionInModule(module: *Module, func: []const u8) ?u64 {
    // Search exports first and private symbols next
    for (module.exports.items) |*exp| {
        if (exp.name) |export_name| {
            if (std.mem.eql(u8, export_name, func)) {
                // Just support direct exports for now, rather than forwarded functions
                switch (exp.target) {
                    .RVA => |rva| return module.address + rva,
                    .Forwarder => continue, // Skip forwarded exports for now
                }
            }
        }
    }
    return null;
}

pub fn resolveAddressToName(allocator: std.mem.Allocator, address: u64, process: *Process) !?[]u8 {
    const module = process.getContainingModuleMut(address) orelse return null;

    var closest: AddressMatch = .none;
    var closest_addr: u64 = 0;

    // Search through exports - this could be faster if we were always in sorted order
    for (module.exports.items) |*exp| {
        switch (exp.target) {
            .RVA => |rva| {
                const export_addr = module.address + rva;
                if (export_addr <= address) {
                    if (closest.isNone() or closest_addr < export_addr) {
                        closest = AddressMatch{ .export_match = exp };
                        closest_addr = export_addr;
                    }
                }
            },
            .Forwarder => continue, // Skip forwarded exports
        }
    }

    // TODO: Add PDB symbol lookup when PDB support is implemented
    // if (module.pdb) |pdb| {
    //     // Search through PDB symbols
    // }

    // Format the result based on what we found
    switch (closest) {
        .export_match => |exp| {
            const offset = address - closest_addr;
            if (offset == 0) {
                return try std.fmt.allocPrint(allocator, "{s}!{s}", .{ module.name, exp.toString() });
            } else {
                return try std.fmt.allocPrint(allocator, "{s}!{s}+0x{X}", .{ module.name, exp.toString(), offset });
            }
        },
        .public => |public_name| {
            const offset = address - closest_addr;
            if (offset == 0) {
                return try std.fmt.allocPrint(allocator, "{s}!{s}", .{ module.name, public_name });
            } else {
                return try std.fmt.allocPrint(allocator, "{s}!{s}+0x{X}", .{ module.name, public_name, offset });
            }
        },
        .none => return null,
    }
}
