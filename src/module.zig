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

// Simplified module structure for now
// TODO: Add full PE parsing, PDB loading, and export table parsing
pub const Module = struct {
    name: []const u8,
    address: u64,
    size: u64,
    allocator: std.mem.Allocator,
    exports: std.ArrayList(Export),
    optional_header: ?IMAGE_OPTIONAL_HEADER64,

    // TODO: Add these fields when implementing full PE parsing
    // pdb_name: ?[]const u8,
    // pdb_info: ?PdbInfo,

    pub fn init(allocator: std.mem.Allocator, address: u64, name: ?[]const u8, mem_source: memory.MemorySource) !Module {
        const module_name = if (name) |n| blk: {
            const owned_name = try allocator.dupe(u8, n);
            break :blk owned_name;
        } else blk: {
            const default_name = try std.fmt.allocPrint(allocator, "module_{x}", .{address});
            break :blk default_name;
        };

        // Try to read PE header from memory
        const optional_header = readPeHeader(allocator, address, mem_source) catch |err| blk: {
            std.debug.print("Warning: Failed to read PE header for {s}: {}\n", .{ module_name, err });
            break :blk null;
        };

        // Use actual module size from PE header if available, otherwise default
        const module_size = if (optional_header) |header|
            header.SizeOfImage
        else
            0x100000; // 1MB default

        return Module{
            .name = module_name,
            .address = address,
            .size = module_size,
            .allocator = allocator,
            .exports = std.ArrayList(Export).init(allocator),
            .optional_header = optional_header,
        };
    }

    pub fn deinit(self: *Module) void {
        self.allocator.free(self.name);
        self.exports.deinit();
    }

    pub fn containsAddress(self: Module, address: u64) bool {
        const end = self.address + self.size;
        return self.address <= address and address < end;
    }

    pub fn getDataDirectory(self: Module, entry: u32) !IMAGE_DATA_DIRECTORY {
        if (self.optional_header) |header| {
            if (entry < header.DataDirectory.len) {
                return header.DataDirectory[entry];
            }
        }
        // Return empty directory if no PE header available
        return IMAGE_DATA_DIRECTORY{ .VirtualAddress = 0, .Size = 0 };
    }

    // TODO: Implement when we add PE parsing
    // pub fn fromMemoryView(allocator: std.mem.Allocator, module_address: u64, module_name: ?[]const u8, memory_source: memory.MemorySource) !Module
    // pub fn readDebugInfo(...)
    // pub fn readExports(...)
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

// TODO: Implement PDB support when needed
// pub const PdbInfo = extern struct {
//     signature: u32,
//     guid: [16]u8, // GUID as bytes
//     age: u32,
// };
