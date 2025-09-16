const std = @import("std");
const windows = std.os.windows;
const print = std.debug.print;
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;

const memory = @import("memory.zig");
const util = @import("util.zig");

// Maximum path length for module names
const MAX_PATH = 260;

// PE constants
const IMAGE_DOS_SIGNATURE = 0x5A4D; // MZ
const IMAGE_NT_SIGNATURE = 0x00004550; // PE00
const IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
const IMAGE_DIRECTORY_ENTRY_DEBUG = 6;
const IMAGE_DEBUG_TYPE_CODEVIEW = 2;

// PE structures
pub const IMAGE_DOS_HEADER = extern struct {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [4]u16,
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [10]u16,
    e_lfanew: i32,
};

pub const IMAGE_FILE_HEADER = extern struct {
    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
};

pub const IMAGE_DATA_DIRECTORY = extern struct {
    VirtualAddress: u32,
    Size: u32,
};

pub const IMAGE_OPTIONAL_HEADER64 = extern struct {
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

pub const IMAGE_NT_HEADERS64 = extern struct {
    Signature: u32,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
};

pub const IMAGE_EXPORT_DIRECTORY = extern struct {
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

pub const IMAGE_DEBUG_DIRECTORY = extern struct {
    Characteristics: u32,
    TimeDateStamp: u32,
    MajorVersion: u16,
    MinorVersion: u16,
    Type: u32,
    SizeOfData: u32,
    AddressOfRawData: u32,
    PointerToRawData: u32,
};

pub const PDB_INFO = extern struct {
    signature: u32,
    guid: [16]u8,
    age: u32,
};

// PE Section header
pub const IMAGE_SECTION_HEADER = extern struct {
    Name: [8]u8,
    VirtualSize: u32,
    VirtualAddress: u32,
    SizeOfRawData: u32,
    PointerToRawData: u32,
    PointerToRelocations: u32,
    PointerToLinenumbers: u32,
    NumberOfRelocations: u16,
    NumberOfLinenumbers: u16,
    Characteristics: u32,
};

// Export target enumeration
pub const ExportTarget = union(enum) {
    RVA: u64,
    Forwarder: []u8,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: Allocator) void {
        switch (self.*) {
            .RVA => {},
            .Forwarder => |name| allocator.free(name),
        }
    }
};

// Export structure
pub const Export = struct {
    name: ?[]u8,
    ordinal: u32,
    target: ExportTarget,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: Allocator) void {
        if (self.name) |name| {
            allocator.free(name);
        }
        self.target.deinit(allocator);
    }

    pub fn toString(self: *const Self, allocator: Allocator) ![]u8 {
        if (self.name) |name| {
            return try allocator.dupe(u8, name);
        } else {
            return try std.fmt.allocPrint(allocator, "#{}", .{self.ordinal});
        }
    }
};

// Module structure
pub const Module = struct {
    base_address: u64,
    size: u32,
    name: []u8,
    exports: ArrayList(Export),
    pdb_name: ?[]u8,
    sections: ArrayList(IMAGE_SECTION_HEADER),

    const Self = @This();

    pub fn init(allocator: Allocator, base_address: u64, name: ?[]const u8, process: windows.HANDLE) !Self {
        var module = Self{
            .base_address = base_address,
            .size = 0,
            .name = undefined,
            .exports = ArrayList(Export).init(allocator),
            .pdb_name = null,
            .sections = ArrayList(IMAGE_SECTION_HEADER).init(allocator),
        };

        // Read DOS header
        const dos_header = memory.readProcessMemoryData(IMAGE_DOS_HEADER, process, base_address) catch |err| {
            print("Failed to read DOS header: {any}\n", .{err});
            return err;
        };

        if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
            return error.InvalidDosSignature;
        }

        // Read PE header
        const pe_header_addr = base_address + @as(u64, @intCast(dos_header.e_lfanew));
        const pe_header = memory.readProcessMemoryData(IMAGE_NT_HEADERS64, process, pe_header_addr) catch |err| {
            print("Failed to read PE header: {any}\n", .{err});
            return err;
        };

        if (pe_header.Signature != IMAGE_NT_SIGNATURE) {
            return error.InvalidPeSignature;
        }

        module.size = pe_header.OptionalHeader.SizeOfImage;

        // Set module name
        if (name) |n| {
            const filename = util.extractFilename(n);
            module.name = try allocator.dupe(u8, filename);
        } else {
            module.name = try allocator.dupe(u8, "unknown");
        }

        // Parse exports
        try module.readExports(allocator, pe_header, process);

        // Parse debug directory for PDB info
        try module.readDebugInfo(allocator, pe_header, process);

        // Read section headers
        try module.readSections(allocator, pe_header, process);

        return module;
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        allocator.free(self.name);
        for (self.exports.items) |*exp| {
            exp.deinit(allocator);
        }
        self.exports.deinit();
        if (self.pdb_name) |pdb_name| {
            allocator.free(pdb_name);
        }
        self.sections.deinit();
    }

    pub fn containsAddress(self: *const Self, address: u64) bool {
        return address >= self.base_address and address < (self.base_address + self.size);
    }

    pub fn findExportByName(self: *const Self, name: []const u8) ?u64 {
        for (self.exports.items) |*exp| {
            if (exp.name) |exp_name| {
                if (std.mem.eql(u8, exp_name, name)) {
                    switch (exp.target) {
                        .RVA => |addr| return addr,
                        .Forwarder => {}, // Skip forwarders for now
                    }
                }
            }
        }
        return null;
    }

    fn readExports(self: *Self, allocator: Allocator, pe_header: IMAGE_NT_HEADERS64, process: windows.HANDLE) !void {
        const export_table_info = pe_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (export_table_info.VirtualAddress == 0) {
            return; // No exports
        }

        const export_table_addr = self.base_address + export_table_info.VirtualAddress;
        const export_table_end = export_table_addr + export_table_info.Size;

        const export_directory = memory.readProcessMemoryData(IMAGE_EXPORT_DIRECTORY, process, export_table_addr) catch |err| {
            print("Failed to read export directory: {any}\n", .{err});
            return err;
        };

        // Update module name from exports if we don't have one
        if (std.mem.eql(u8, self.name, "unknown") and export_directory.Name != 0) {
            const name_addr = self.base_address + export_directory.Name;
            const new_name = memory.readProcessMemoryString(allocator, process, name_addr, 512, false) catch {
                return;
            };
            allocator.free(self.name);
            self.name = new_name;
        }

        // Read address table
        const address_table_address = self.base_address + export_directory.AddressOfFunctions;
        const address_table = memory.readProcessMemoryArray(u32, allocator, process, address_table_address, export_directory.NumberOfFunctions) catch |err| {
            print("Failed to read address table: {any}\n", .{err});
            return err;
        };
        defer allocator.free(address_table);

        // Read ordinal and name arrays
        const ordinal_array_address = self.base_address + export_directory.AddressOfNameOrdinals;
        const ordinal_array = memory.readProcessMemoryArray(u16, allocator, process, ordinal_array_address, export_directory.NumberOfNames) catch |err| {
            print("Failed to read ordinal array: {any}\n", .{err});
            return err;
        };
        defer allocator.free(ordinal_array);

        const name_array_address = self.base_address + export_directory.AddressOfNames;
        const name_array = memory.readProcessMemoryArray(u32, allocator, process, name_array_address, export_directory.NumberOfNames) catch |err| {
            print("Failed to read name array: {any}\n", .{err});
            return err;
        };
        defer allocator.free(name_array);

        // Process each export
        for (address_table, 0..) |function_address, unbiased_ordinal| {
            const ordinal = export_directory.Base + @as(u32, @intCast(unbiased_ordinal));
            const target_address = self.base_address + function_address;

            // Find name for this ordinal
            var export_name: ?[]u8 = null;
            for (ordinal_array, 0..) |ord, name_idx| {
                if (ord == @as(u16, @intCast(unbiased_ordinal))) {
                    const name_address = self.base_address + name_array[name_idx];
                    export_name = memory.readProcessMemoryString(allocator, process, name_address, 4096, false) catch |err| {
                        print("Failed to read export name: {any}\n", .{err});
                        continue;
                    };
                    break;
                }
            }

            // Check if this is a forwarder
            var target: ExportTarget = undefined;
            if (target_address >= export_table_addr and target_address < export_table_end) {
                // This is a forwarder
                const forwarding_name = memory.readProcessMemoryString(allocator, process, target_address, 4096, false) catch |err| {
                    print("Failed to read forwarder name: {any}\n", .{err});
                    if (export_name) |name| allocator.free(name);
                    continue;
                };
                target = ExportTarget{ .Forwarder = forwarding_name };
            } else {
                // Normal export
                target = ExportTarget{ .RVA = target_address };
            }

            try self.exports.append(Export{
                .name = export_name,
                .ordinal = ordinal,
                .target = target,
            });
        }
    }

    fn readDebugInfo(self: *Self, allocator: Allocator, pe_header: IMAGE_NT_HEADERS64, process: windows.HANDLE) !void {
        const debug_table_info = pe_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        if (debug_table_info.VirtualAddress == 0) {
            return; // No debug info
        }

        const dir_size = @sizeOf(IMAGE_DEBUG_DIRECTORY);
        const count = @min(debug_table_info.Size / dir_size, 20); // Limit to 20 entries

        for (0..count) |dir_index| {
            const debug_directory_address = self.base_address + debug_table_info.VirtualAddress + (dir_index * dir_size);
            const debug_directory = memory.readProcessMemoryData(IMAGE_DEBUG_DIRECTORY, process, debug_directory_address) catch |err| {
                print("Failed to read debug directory: {any}\n", .{err});
                continue;
            };

            if (debug_directory.Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
                const pdb_info_address = self.base_address + debug_directory.AddressOfRawData;
                _ = memory.readProcessMemoryData(PDB_INFO, process, pdb_info_address) catch |err| {
                    print("Failed to read PDB info: {any}\n", .{err});
                    continue;
                };

                // Read PDB name
                const pdb_name_address = pdb_info_address + @sizeOf(PDB_INFO);
                self.pdb_name = memory.readProcessMemoryString(allocator, process, pdb_name_address, MAX_PATH, false) catch |err| {
                    print("Failed to read PDB name: {any}\n", .{err});
                    continue;
                };

                break;
            }
        }
    }

    fn readSections(self: *Self, _: Allocator, pe_header: IMAGE_NT_HEADERS64, process: windows.HANDLE) !void {
        // Section headers come right after the optional header
        const dos_header_addr = self.base_address;
        const dos_header = memory.readProcessMemoryData(IMAGE_DOS_HEADER, process, dos_header_addr) catch return;

        const pe_header_addr = self.base_address + @as(u64, @intCast(dos_header.e_lfanew));
        const sections_addr = pe_header_addr + @sizeOf(IMAGE_NT_HEADERS64);

        for (0..pe_header.FileHeader.NumberOfSections) |i| {
            const section_addr = sections_addr + (i * @sizeOf(IMAGE_SECTION_HEADER));
            const section = memory.readProcessMemoryData(IMAGE_SECTION_HEADER, process, section_addr) catch |err| {
                print("Failed to read section header {}: {any}\n", .{ i, err });
                continue;
            };
            try self.sections.append(section);
        }
    }

    pub fn findSection(self: *const Self, name: []const u8) ?*const IMAGE_SECTION_HEADER {
        for (self.sections.items) |*section| {
            const section_name = std.mem.sliceTo(&section.Name, 0);
            if (std.mem.eql(u8, section_name, name)) {
                return section;
            }
        }
        return null;
    }

    pub fn getPDataSection(self: *const Self) ?*const IMAGE_SECTION_HEADER {
        return self.findSection(".pdata");
    }
};