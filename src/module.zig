const std = @import("std");
const memory = @import("memory.zig");
const windows = std.os.windows;

// PE header structures
const IMAGE_DATA_DIRECTORY = packed struct {
    VirtualAddress: u32,
    Size: u32,
};

const IMAGE_DOS_HEADER = extern struct {
    e_magic: u16, // "MZ" signature
    e_cblp: u16, // Bytes on last page of file
    e_cp: u16, // Pages in file
    e_crlc: u16, // Relocations
    e_cparhdr: u16, // Size of header in paragraphs
    e_minalloc: u16, // Minimum extra paragraphs needed
    e_maxalloc: u16, // Maximum extra paragraphs needed
    e_ss: u16, // Initial relative SS value
    e_sp: u16, // Initial SP value
    e_csum: u16, // Checksum
    e_ip: u16, // Initial IP value
    e_cs: u16, // Initial relative CS value
    e_lfarlc: u16, // File address of relocation table
    e_ovno: u16, // Overlay number
    e_res: [4]u16, // Reserved words
    e_oemid: u16, // OEM identifier
    e_oeminfo: u16, // OEM information
    e_res2: [10]u16, // Reserved words
    e_lfanew: u32, // File address of new exe header
};

const IMAGE_FILE_HEADER = extern struct {
    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
};

const IMAGE_OPTIONAL_HEADER64 = extern struct {
    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    ImageBase: u64,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
    SizeOfStackReserve: u64,
    SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64,
    SizeOfHeapCommit: u64,
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};

const IMAGE_NT_HEADERS64 = extern struct {
    Signature: u32, // "PE\0\0"
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
};

// PE signatures
const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // "PE\0\0"

// Debug directory structures
const IMAGE_DEBUG_DIRECTORY = extern struct {
    Characteristics: u32,
    TimeDateStamp: u32,
    MajorVersion: u16,
    MinorVersion: u16,
    Type: u32,
    SizeOfData: u32,
    AddressOfRawData: u32,
    PointerToRawData: u32,
};

// Export directory structure
const IMAGE_EXPORT_DIRECTORY = extern struct {
    Characteristics: u32,
    TimeDateStamp: u32,
    MajorVersion: u16,
    MinorVersion: u16,
    Name: u32,
    Base: u32,
    NumberOfFunctions: u32,
    NumberOfNames: u32,
    AddressOfFunctions: u32,
    AddressOfNames: u32,
    AddressOfNameOrdinals: u32,
};

// Directory entry indices
const IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
const IMAGE_DIRECTORY_ENTRY_DEBUG = 6;

// Debug directory type constants
const IMAGE_DEBUG_TYPE_CODEVIEW = 2;

// Machine architecture constants
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

// PDB structures
const PdbInfo = extern struct {
    signature: u32,
    guid: [16]u8, // GUID as bytes
    age: u32,
};

// Read PE header from memory
fn readPeHeader(allocator: std.mem.Allocator, module_address: u64, mem_source: memory.MemorySource) !IMAGE_OPTIONAL_HEADER64 {
    // Read DOS header
    const dos_header = memory.readMemoryData(IMAGE_DOS_HEADER, mem_source, module_address, allocator) catch return error.MemoryReadError;

    // Verify DOS signature
    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        return error.InvalidDosSignature;
    }

    // Calculate PE header address
    const pe_header_address = module_address + dos_header.e_lfanew;

    // Read NT headers
    const nt_headers = memory.readMemoryData(IMAGE_NT_HEADERS64, mem_source, pe_header_address, allocator) catch return error.MemoryReadError;

    // Verify PE signature
    if (nt_headers.Signature != IMAGE_NT_SIGNATURE) {
        return error.InvalidPeSignature;
    }

    return nt_headers.OptionalHeader;
}

fn readPeHeaderFull(allocator: std.mem.Allocator, module_address: u64, mem_source: memory.MemorySource) !IMAGE_NT_HEADERS64 {
    // Read DOS header
    const dos_header = memory.readMemoryData(IMAGE_DOS_HEADER, mem_source, module_address, allocator) catch return error.MemoryReadError;

    // Verify DOS signature
    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        return error.InvalidDosSignature;
    }

    // Calculate PE header address
    const pe_header_address = module_address + dos_header.e_lfanew;

    // Read NT headers
    const nt_headers = memory.readMemoryData(IMAGE_NT_HEADERS64, mem_source, pe_header_address, allocator) catch return error.MemoryReadError;

    // Verify PE signature
    if (nt_headers.Signature != IMAGE_NT_SIGNATURE) {
        return error.InvalidPeSignature;
    }

    return nt_headers;
}

fn readDebugInfo(allocator: std.mem.Allocator, pe_header: IMAGE_NT_HEADERS64, module_address: u64, mem_source: memory.MemorySource) !struct { pdb_info: ?PdbInfo, pdb_name: ?[]const u8 } {
    var pdb_info: ?PdbInfo = null;
    var pdb_name: ?[]const u8 = null;

    const debug_table_info = pe_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (debug_table_info.VirtualAddress != 0) {
        const dir_size = @sizeOf(IMAGE_DEBUG_DIRECTORY);
        // Limit to 20 entries to keep it sane
        const count = @min(debug_table_info.Size / dir_size, 20);

        for (0..count) |dir_index| {
            const debug_directory_address = module_address + debug_table_info.VirtualAddress + (dir_index * dir_size);
            const debug_directory = memory.readMemoryData(IMAGE_DEBUG_DIRECTORY, mem_source, debug_directory_address, allocator) catch continue;

            if (debug_directory.Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
                const pdb_info_address = debug_directory.AddressOfRawData + module_address;
                pdb_info = memory.readMemoryData(PdbInfo, mem_source, pdb_info_address, allocator) catch null;

                if (pdb_info != null) {
                    // Read PDB name (null-terminated string after PdbInfo struct)
                    const pdb_name_address = pdb_info_address + @sizeOf(PdbInfo);
                    const max_size = debug_directory.SizeOfData - @sizeOf(PdbInfo);
                    pdb_name = memory.readMemoryString(mem_source, pdb_name_address, max_size, false, allocator) catch null;
                }
                break;
            }
        }
    }

    return .{ .pdb_info = pdb_info, .pdb_name = pdb_name };
}

fn readExports(allocator: std.mem.Allocator, pe_header: IMAGE_NT_HEADERS64, module_address: u64, mem_source: memory.MemorySource) !struct { exports: []Export, module_name: ?[]const u8 } {
    var exports = std.ArrayList(Export).init(allocator);
    defer exports.deinit();
    var module_name: ?[]const u8 = null;

    const export_table_info = pe_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_table_info.VirtualAddress != 0) {
        const export_table_addr = module_address + export_table_info.VirtualAddress;
        const export_table_end = export_table_addr + export_table_info.Size;
        const export_directory = memory.readMemoryData(IMAGE_EXPORT_DIRECTORY, mem_source, export_table_addr, allocator) catch {
            return .{ .exports = try exports.toOwnedSlice(), .module_name = module_name };
        };

        // Get module name from export directory
        if (export_directory.Name != 0) {
            const name_addr = module_address + export_directory.Name;
            module_name = memory.readMemoryString(mem_source, name_addr, 512, false, allocator) catch null;
        }

        // Read the name table (parallel arrays of ordinals and name pointers)
        const ordinal_array_address = module_address + export_directory.AddressOfNameOrdinals;
        const ordinal_array = memory.readMemoryFullArray(u16, mem_source, ordinal_array_address, export_directory.NumberOfNames, allocator) catch {
            return .{ .exports = try exports.toOwnedSlice(), .module_name = module_name };
        };
        defer allocator.free(ordinal_array);

        const name_array_address = module_address + export_directory.AddressOfNames;
        const name_array = memory.readMemoryFullArray(u32, mem_source, name_array_address, export_directory.NumberOfNames, allocator) catch {
            return .{ .exports = try exports.toOwnedSlice(), .module_name = module_name };
        };
        defer allocator.free(name_array);

        const address_table_address = module_address + export_directory.AddressOfFunctions;
        const address_table = memory.readMemoryFullArray(u32, mem_source, address_table_address, export_directory.NumberOfFunctions, allocator) catch {
            return .{ .exports = try exports.toOwnedSlice(), .module_name = module_name };
        };
        defer allocator.free(address_table);

        for (address_table, 0..) |function_address, unbiased_ordinal| {
            const ordinal = export_directory.Base + @as(u32, @intCast(unbiased_ordinal));
            const target_address = module_address + function_address;

            // Find name for this ordinal
            var name_index: ?usize = null;
            for (ordinal_array, 0..) |ord, idx| {
                if (ord == unbiased_ordinal) {
                    name_index = idx;
                    break;
                }
            }

            const export_name = if (name_index) |idx| blk: {
                const name_address = module_address + name_array[idx];
                const name_str = memory.readMemoryString(mem_source, name_address, 4096, false, allocator) catch null;
                break :blk name_str;
            } else null;

            // An address that falls inside the export directory is actually a forwarder
            const target = if (target_address >= export_table_addr and target_address < export_table_end) blk: {
                const forwarding_name = memory.readMemoryString(mem_source, target_address, 4096, false, allocator) catch {
                    break :blk ExportTarget{ .RVA = target_address };
                };
                break :blk ExportTarget{ .Forwarder = forwarding_name };
            } else blk: {
                break :blk ExportTarget{ .RVA = target_address };
            };

            try exports.append(Export{
                .name = export_name,
                .ordinal = ordinal,
                .target = target,
            });
        }
    }

    return .{ .exports = try exports.toOwnedSlice(), .module_name = module_name };
}

pub const Module = struct {
    name: []const u8,
    address: u64,
    size: u64,
    allocator: std.mem.Allocator,
    exports: std.ArrayList(Export),
    optional_header: ?IMAGE_OPTIONAL_HEADER64,
    pe_header: ?IMAGE_NT_HEADERS64,
    pdb_name: ?[]const u8,
    pdb_info: ?PdbInfo,

    pub fn init(allocator: std.mem.Allocator, address: u64, name: ?[]const u8, mem_source: memory.MemorySource) !Module {
        return fromMemoryView(allocator, address, name, mem_source);
    }

    pub fn fromMemoryView(allocator: std.mem.Allocator, module_address: u64, module_name: ?[]const u8, mem_source: memory.MemorySource) !Module {
        // Read full PE header
        const pe_header = readPeHeaderFull(allocator, module_address, mem_source) catch |err| {
            const fallback_name = if (module_name) |n| blk: {
                const owned_name = try allocator.dupe(u8, n);
                break :blk owned_name;
            } else blk: {
                const default_name = try std.fmt.allocPrint(allocator, "module_{x}", .{module_address});
                break :blk default_name;
            };

            std.debug.print("Warning: Failed to read PE header for {s}: {}\n", .{ fallback_name, err });

            return Module{
                .name = fallback_name,
                .address = module_address,
                .size = 0x100000, // 1MB default
                .allocator = allocator,
                .exports = std.ArrayList(Export).init(allocator),
                .optional_header = null,
                .pe_header = null,
                .pdb_name = null,
                .pdb_info = null,
            };
        };

        // Check machine architecture
        if (pe_header.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
            return error.UnsupportedMachineArchitecture;
        }

        const size = pe_header.OptionalHeader.SizeOfImage;

        // Read debug info (PDB)
        const debug_result = readDebugInfo(allocator, pe_header, module_address, mem_source) catch .{ .pdb_info = null, .pdb_name = null };

        // Read exports
        var exports_list = std.ArrayList(Export).init(allocator);
        var export_module_name: ?[]const u8 = null;

        if (readExports(allocator, pe_header, module_address, mem_source)) |result| {
            exports_list.appendSlice(result.exports) catch {};
            export_module_name = result.module_name;
            if (result.exports.len > 0) {
                allocator.free(result.exports);
            }
        } else |err| {
            std.debug.print("Warning: Failed to read exports: {}\n", .{err});
        }

        // Determine final module name (prefer export table name, then provided name, then fallback)
        const final_name = if (export_module_name) |n|
            n
        else if (module_name) |n|
            try allocator.dupe(u8, n)
        else
            try std.fmt.allocPrint(allocator, "module_{X}", .{module_address});

        return Module{
            .name = final_name,
            .address = module_address,
            .size = size,
            .allocator = allocator,
            .exports = exports_list,
            .optional_header = pe_header.OptionalHeader,
            .pe_header = pe_header,
            .pdb_name = debug_result.pdb_name,
            .pdb_info = debug_result.pdb_info,
        };
    }

    pub fn deinit(self: *Module) void {
        self.allocator.free(self.name);
        if (self.pdb_name) |pdb_name| {
            self.allocator.free(pdb_name);
        }

        // Free export names and forwarder names
        for (self.exports.items) |exp| {
            if (exp.name) |name| {
                self.allocator.free(name);
            }
            switch (exp.target) {
                .Forwarder => |fwd| self.allocator.free(fwd),
                .RVA => {},
            }
        }
        self.exports.deinit();
    }

    pub fn containsAddress(self: Module, address: u64) bool {
        const end = self.address + self.size;
        return self.address <= address and address < end;
    }

    pub fn getDataDirectory(self: Module, entry: u32) IMAGE_DATA_DIRECTORY {
        if (self.pe_header) |pe_header| {
            if (entry < pe_header.OptionalHeader.DataDirectory.len) {
                return pe_header.OptionalHeader.DataDirectory[entry];
            }
        }
        // Return empty directory if no PE header available
        return IMAGE_DATA_DIRECTORY{ .VirtualAddress = 0, .Size = 0 };
    }
};

pub const Export = struct {
    name: ?[]const u8,
    ordinal: u32,
    target: ExportTarget,

    pub fn toString(self: Export) []const u8 {
        return if (self.name) |name| name else "unnamed";
    }
};

pub const ExportTarget = union(enum) {
    RVA: u64,
    Forwarder: []const u8,
};
