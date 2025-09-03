const std = @import("std");
const windows = std.os.windows;
const print = std.debug.print;
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;

// Windows API constants
const INFINITE = windows.INFINITE;
const DEBUG_ONLY_THIS_PROCESS = 0x00000002;
const CREATE_NEW_CONSOLE = 0x00000010;
const FALSE = windows.FALSE;

// Debug event codes
const EXCEPTION_DEBUG_EVENT = 1;
const CREATE_THREAD_DEBUG_EVENT = 2;
const CREATE_PROCESS_DEBUG_EVENT = 3;
const EXIT_THREAD_DEBUG_EVENT = 4;
const EXIT_PROCESS_DEBUG_EVENT = 5;
const LOAD_DLL_DEBUG_EVENT = 6;
const UNLOAD_DLL_DEBUG_EVENT = 7;
const OUTPUT_DEBUG_STRING_EVENT = 8;
const RIP_EVENT = 9;

const DBG_CONTINUE = 0x00010002;
const DBG_EXCEPTION_NOT_HANDLED = 0x80010001;

// Exception codes
const EXCEPTION_SINGLE_STEP = 0x80000004;

// Thread access rights
const THREAD_GET_CONTEXT = 0x0008;
const THREAD_SET_CONTEXT = 0x0010;

// Context flags for x64
const CONTEXT_AMD64 = 0x00100000;
const CONTEXT_CONTROL = CONTEXT_AMD64 | 0x00000001;
const CONTEXT_INTEGER = CONTEXT_AMD64 | 0x00000002;
const CONTEXT_SEGMENTS = CONTEXT_AMD64 | 0x00000004;
const CONTEXT_FLOATING_POINT = CONTEXT_AMD64 | 0x00000008;
const CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x00000010;
const CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS;

// Trap flag for single stepping
const TRAP_FLAG = 1 << 8;

// Maximum path length for module names
const MAX_PATH = 260;

// PE constants
const IMAGE_DOS_SIGNATURE = 0x5A4D; // MZ
const IMAGE_NT_SIGNATURE = 0x00004550; // PE00
const IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
const IMAGE_DIRECTORY_ENTRY_DEBUG = 6;
const IMAGE_DEBUG_TYPE_CODEVIEW = 2;

// PE structures
const IMAGE_DOS_HEADER = extern struct {
    e_magic: u16, // Magic number
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
    e_lfanew: i32, // File address of new exe header
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

const IMAGE_DATA_DIRECTORY = extern struct {
    VirtualAddress: u32,
    Size: u32,
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
    Signature: u32,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
};

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

const PDB_INFO = extern struct {
    signature: u32,
    guid: [16]u8, // GUID as bytes
    age: u32,
    // Null terminated name goes after the end
};

// Debug event structures (keeping existing ones)
const DEBUG_EVENT = extern struct {
    dwDebugEventCode: windows.DWORD,
    dwProcessId: windows.DWORD,
    dwThreadId: windows.DWORD,
    u: extern union {
        Exception: EXCEPTION_DEBUG_INFO,
        CreateThread: CREATE_THREAD_DEBUG_INFO,
        CreateProcessInfo: CREATE_PROCESS_DEBUG_INFO,
        ExitThread: EXIT_THREAD_DEBUG_INFO,
        ExitProcess: EXIT_PROCESS_DEBUG_INFO,
        LoadDll: LOAD_DLL_DEBUG_INFO,
        UnloadDll: UNLOAD_DLL_DEBUG_INFO,
        DebugString: OUTPUT_DEBUG_STRING_INFO,
        RipInfo: RIP_INFO,
    },
};

const EXCEPTION_DEBUG_INFO = extern struct {
    ExceptionRecord: EXCEPTION_RECORD,
    dwFirstChance: windows.DWORD,
};

const EXCEPTION_RECORD = extern struct {
    ExceptionCode: windows.DWORD,
    ExceptionFlags: windows.DWORD,
    ExceptionRecord: ?*EXCEPTION_RECORD,
    ExceptionAddress: ?*anyopaque,
    NumberParameters: windows.DWORD,
    ExceptionInformation: [15]usize,
};

const CREATE_THREAD_DEBUG_INFO = extern struct {
    hThread: windows.HANDLE,
    lpThreadLocalBase: ?*anyopaque,
    lpStartAddress: ?*anyopaque,
};

const CREATE_PROCESS_DEBUG_INFO = extern struct {
    hFile: windows.HANDLE,
    hProcess: windows.HANDLE,
    hThread: windows.HANDLE,
    lpBaseOfImage: ?*anyopaque,
    dwDebugInfoFileOffset: windows.DWORD,
    nDebugInfoSize: windows.DWORD,
    lpThreadLocalBase: ?*anyopaque,
    lpStartAddress: ?*anyopaque,
    lpImageName: ?*anyopaque,
    fUnicode: windows.WORD,
};

const EXIT_THREAD_DEBUG_INFO = extern struct {
    dwExitCode: windows.DWORD,
};

const EXIT_PROCESS_DEBUG_INFO = extern struct {
    dwExitCode: windows.DWORD,
};

const LOAD_DLL_DEBUG_INFO = extern struct {
    hFile: windows.HANDLE,
    lpBaseOfDll: ?*anyopaque,
    dwDebugInfoFileOffset: windows.DWORD,
    nDebugInfoSize: windows.DWORD,
    lpImageName: ?*anyopaque,
    fUnicode: windows.WORD,
};

const UNLOAD_DLL_DEBUG_INFO = extern struct {
    lpBaseOfDll: ?*anyopaque,
};

const OUTPUT_DEBUG_STRING_INFO = extern struct {
    lpDebugStringData: ?*anyopaque,
    fUnicode: windows.WORD,
    nDebugStringLength: windows.WORD,
};

const RIP_INFO = extern struct {
    dwError: windows.DWORD,
    dwType: windows.DWORD,
};

const STARTUPINFOEXW = extern struct {
    StartupInfo: STARTUPINFOW,
    lpAttributeList: ?*anyopaque,
};

const STARTUPINFOW = extern struct {
    cb: windows.DWORD,
    lpReserved: ?[*:0]u16,
    lpDesktop: ?[*:0]u16,
    lpTitle: ?[*:0]u16,
    dwX: windows.DWORD,
    dwY: windows.DWORD,
    dwXSize: windows.DWORD,
    dwYSize: windows.DWORD,
    dwXCountChars: windows.DWORD,
    dwYCountChars: windows.DWORD,
    dwFillAttribute: windows.DWORD,
    dwFlags: windows.DWORD,
    wShowWindow: windows.WORD,
    cbReserved2: windows.WORD,
    lpReserved2: ?[*]u8,
    hStdInput: windows.HANDLE,
    hStdOutput: windows.HANDLE,
    hStdError: windows.HANDLE,
};

const PROCESS_INFORMATION = extern struct {
    hProcess: windows.HANDLE,
    hThread: windows.HANDLE,
    dwProcessId: windows.DWORD,
    dwThreadId: windows.DWORD,
};

// 16-byte aligned context structure for x64
const AlignedContext = struct {
    context: windows.CONTEXT,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .context = std.mem.zeroes(windows.CONTEXT),
        };
    }
};

// Auto-closing handle wrapper
const AutoClosedHandle = struct {
    handle: windows.HANDLE,

    const Self = @This();

    pub fn init(handle: windows.HANDLE) Self {
        return Self{ .handle = handle };
    }

    pub fn deinit(self: *Self) void {
        _ = CloseHandle(self.handle);
    }

    pub fn getHandle(self: *const Self) windows.HANDLE {
        return self.handle;
    }
};

// Export target enumeration
const ExportTarget = union(enum) {
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
const Export = struct {
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
const Module = struct {
    base_address: u64,
    size: u32,
    name: []u8,
    exports: ArrayList(Export),
    pdb_name: ?[]u8,

    const Self = @This();

    pub fn init(allocator: Allocator, base_address: u64, name: ?[]const u8, process: windows.HANDLE) !Self {
        var module = Self{
            .base_address = base_address,
            .size = 0,
            .name = undefined,
            .exports = ArrayList(Export).init(allocator),
            .pdb_name = null,
        };

        // Read DOS header
        const dos_header = readProcessMemoryData(IMAGE_DOS_HEADER, process, base_address) catch |err| {
            print("Failed to read DOS header: {any}\n", .{err});
            return err;
        };

        if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
            print("Invalid DOS signature\n", .{});
            return error.InvalidDosSignature;
        }

        // Read PE header
        const pe_header_addr = base_address + @as(u64, @intCast(dos_header.e_lfanew));
        const pe_header = readProcessMemoryData(IMAGE_NT_HEADERS64, process, pe_header_addr) catch |err| {
            print("Failed to read PE header: {any}\n", .{err});
            return err;
        };

        if (pe_header.Signature != IMAGE_NT_SIGNATURE) {
            print("Invalid PE signature\n", .{});
            return error.InvalidPeSignature;
        }

        module.size = pe_header.OptionalHeader.SizeOfImage;

        // Set module name
        if (name) |n| {
            module.name = try allocator.dupe(u8, n);
        } else {
            module.name = try allocator.dupe(u8, "unknown");
        }

        // Parse exports
        try module.readExports(allocator, pe_header, process);

        // Parse debug directory for PDB info
        try module.readDebugInfo(allocator, pe_header, process);

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
    }

    pub fn containsAddress(self: *const Self, address: u64) bool {
        return address >= self.base_address and address < (self.base_address + self.size);
    }

    fn readExports(self: *Self, allocator: Allocator, pe_header: IMAGE_NT_HEADERS64, process: windows.HANDLE) !void {
        const export_table_info = pe_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (export_table_info.VirtualAddress == 0) {
            return; // No exports
        }

        const export_table_addr = self.base_address + export_table_info.VirtualAddress;
        const export_table_end = export_table_addr + export_table_info.Size;

        const export_directory = readProcessMemoryData(IMAGE_EXPORT_DIRECTORY, process, export_table_addr) catch |err| {
            print("Failed to read export directory: {any}\n", .{err});
            return err;
        };

        // Update module name from exports if we don't have one
        if (std.mem.eql(u8, self.name, "unknown") and export_directory.Name != 0) {
            const name_addr = self.base_address + export_directory.Name;
            const new_name = readProcessMemoryString(allocator, process, name_addr, 512, false) catch {
                // Keep the old name if we can't read the new one
                return;
            };
            allocator.free(self.name);
            self.name = new_name;
        }

        // Read address table
        const address_table_address = self.base_address + export_directory.AddressOfFunctions;
        const address_table = readProcessMemoryArray(u32, allocator, process, address_table_address, export_directory.NumberOfFunctions) catch |err| {
            print("Failed to read address table: {any}\n", .{err});
            return err;
        };
        defer allocator.free(address_table);

        // Read ordinal and name arrays
        const ordinal_array_address = self.base_address + export_directory.AddressOfNameOrdinals;
        const ordinal_array = readProcessMemoryArray(u16, allocator, process, ordinal_array_address, export_directory.NumberOfNames) catch |err| {
            print("Failed to read ordinal array: {any}\n", .{err});
            return err;
        };
        defer allocator.free(ordinal_array);

        const name_array_address = self.base_address + export_directory.AddressOfNames;
        const name_array = readProcessMemoryArray(u32, allocator, process, name_array_address, export_directory.NumberOfNames) catch |err| {
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
                    export_name = readProcessMemoryString(allocator, process, name_address, 4096, false) catch |err| {
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
                const forwarding_name = readProcessMemoryString(allocator, process, target_address, 4096, false) catch |err| {
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
            const debug_directory = readProcessMemoryData(IMAGE_DEBUG_DIRECTORY, process, debug_directory_address) catch |err| {
                print("Failed to read debug directory: {any}\n", .{err});
                continue;
            };

            if (debug_directory.Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
                const pdb_info_address = self.base_address + debug_directory.AddressOfRawData;
                // const pdb_info = readProcessMemoryData(PDB_INFO, process, pdb_info_address) catch |err| {
                _ = readProcessMemoryData(PDB_INFO, process, pdb_info_address) catch |err| {
                    print("Failed to read PDB info: {any}\n", .{err});
                    continue;
                };

                // Read PDB name
                const pdb_name_address = pdb_info_address + @sizeOf(PDB_INFO);
                self.pdb_name = readProcessMemoryString(allocator, process, pdb_name_address, MAX_PATH, false) catch |err| {
                    print("Failed to read PDB name: {any}\n", .{err});
                    continue;
                };

                // We found the CodeView entry, so we're done
                break;
            }
        }
    }
};

// Process structure to track modules
const Process = struct {
    modules: ArrayList(Module),

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .modules = ArrayList(Module).init(allocator),
        };
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        for (self.modules.items) |*module| {
            module.deinit(allocator);
        }
        self.modules.deinit();
    }

    pub fn addModule(self: *Self, allocator: Allocator, address: u64, name: ?[]const u8, process: windows.HANDLE) !*Module {
        const module = Module.init(allocator, address, name, process) catch |err| {
            print("Failed to create module: {any}\n", .{err});
            return err;
        };

        try self.modules.append(module);
        return &self.modules.items[self.modules.items.len - 1];
    }

    pub fn getContainingModule(self: *Self, address: u64) ?*Module {
        for (self.modules.items) |*module| {
            if (module.containsAddress(address)) {
                return module;
            }
        }
        return null;
    }
};

// Expression types for evaluation
const EvalExpr = union(enum) {
    Number: u64,
    Add: struct {
        left: *EvalExpr,
        right: *EvalExpr,
    },

    const Self = @This();

    pub fn deinit(self: *Self, allocator: Allocator) void {
        switch (self.*) {
            .Number => {},
            .Add => |add| {
                add.left.deinit(allocator);
                add.right.deinit(allocator);
                allocator.destroy(add.left);
                allocator.destroy(add.right);
            },
        }
    }

    pub fn evaluate(self: *const Self) u64 {
        return switch (self.*) {
            .Number => |n| n,
            .Add => |add| add.left.evaluate() + add.right.evaluate(),
        };
    }
};

// Command enumeration with parameters
const Command = union(enum) {
    StepInto,
    Go,
    DisplayRegisters,
    DisplayBytes: u64, // address to display
    Evaluate: u64, // expression to evaluate
    ListNearest: u64, // address to lookup nearest symbol
    Quit,
    Unknown,
};

// External Windows API functions
extern "kernel32" fn GetCommandLineW() callconv(windows.WINAPI) [*:0]u16;

extern "kernel32" fn CreateProcessW(
    lpApplicationName: ?[*:0]const u16,
    lpCommandLine: ?[*:0]u16,
    lpProcessAttributes: ?*anyopaque,
    lpThreadAttributes: ?*anyopaque,
    bInheritHandles: windows.BOOL,
    dwCreationFlags: windows.DWORD,
    lpEnvironment: ?*anyopaque,
    lpCurrentDirectory: ?[*:0]const u16,
    lpStartupInfo: *STARTUPINFOW,
    lpProcessInformation: *PROCESS_INFORMATION,
) callconv(windows.WINAPI) windows.BOOL;

extern "kernel32" fn WaitForDebugEventEx(
    lpDebugEvent: *DEBUG_EVENT,
    dwMilliseconds: windows.DWORD,
) callconv(windows.WINAPI) windows.BOOL;

extern "kernel32" fn ContinueDebugEvent(
    dwProcessId: windows.DWORD,
    dwThreadId: windows.DWORD,
    dwContinueStatus: windows.DWORD,
) callconv(windows.WINAPI) windows.BOOL;

extern "kernel32" fn CloseHandle(hObject: windows.HANDLE) callconv(windows.WINAPI) windows.BOOL;

extern "kernel32" fn OpenThread(
    dwDesiredAccess: windows.DWORD,
    bInheritHandle: windows.BOOL,
    dwThreadId: windows.DWORD,
) callconv(windows.WINAPI) windows.HANDLE;

extern "kernel32" fn GetThreadContext(
    hThread: windows.HANDLE,
    lpContext: *windows.CONTEXT,
) callconv(windows.WINAPI) windows.BOOL;

extern "kernel32" fn SetThreadContext(
    hThread: windows.HANDLE,
    lpContext: *const windows.CONTEXT,
) callconv(windows.WINAPI) windows.BOOL;

extern "kernel32" fn ReadProcessMemory(
    hProcess: windows.HANDLE,
    lpBaseAddress: ?*const anyopaque,
    lpBuffer: [*]u8,
    nSize: usize,
    lpNumberOfBytesRead: ?*usize,
) callconv(windows.WINAPI) windows.BOOL;

// Helper function to calculate length of null-terminated wide string
fn wcslen(ptr: [*:0]const u16) usize {
    var len: usize = 0;
    while (ptr[len] != 0) {
        len += 1;
    }
    return len;
}

fn showUsage(error_message: []const u8) void {
    print("Error: {s}\n", .{error_message});
    print("Usage: zig-debugger <Command Line>\n", .{});
}

// Parse command line to extract the target process command line
fn parseCommandLine(allocator: Allocator) ![]u16 {
    const cmd_line_ptr = GetCommandLineW();
    const cmd_line_len = wcslen(cmd_line_ptr);
    const cmd_line = cmd_line_ptr[0..cmd_line_len];

    if (cmd_line.len == 0) {
        return error.EmptyCommandLine;
    }

    var i: usize = 0;
    const first_char = cmd_line[0];

    // If the first character is a quote, find the matching end quote. Otherwise, find the first space.
    const end_char: u16 = if (first_char == '"') '"' else ' ';

    // Skip the first character
    i = 1;

    // Find the end of the executable name
    while (i < cmd_line.len and cmd_line[i] != end_char) {
        i += 1;
    }

    if (i >= cmd_line.len) {
        return error.NoArgumentsFound;
    }

    // Skip the end character (quote or space)
    i += 1;

    // Skip any whitespace
    while (i < cmd_line.len and cmd_line[i] == ' ') {
        i += 1;
    }

    if (i >= cmd_line.len) {
        return error.NoArgumentsFound;
    }

    // Copy the remaining command line arguments
    const remaining_len = cmd_line.len - i;
    var result = try allocator.alloc(u16, remaining_len + 1); // +1 for null terminator
    @memcpy(result[0..remaining_len], cmd_line[i..]);
    result[remaining_len] = 0; // Null terminate

    return result;
}

// Parse integer from string (hex or decimal)
fn parseInt(text: []const u8) !u64 {
    const trimmed = std.mem.trim(u8, text, " \t");
    if (std.mem.startsWith(u8, trimmed, "0x") or std.mem.startsWith(u8, trimmed, "0X")) {
        const hex_part = trimmed[2..];
        return try std.fmt.parseInt(u64, hex_part, 16);
    } else {
        return try std.fmt.parseInt(u64, trimmed, 10);
    }
}

// Simple expression parser (replacing rust-sitter)
fn parseExpression(allocator: Allocator, text: []const u8) !EvalExpr {
    const trimmed = std.mem.trim(u8, text, " \t");

    var i: usize = 0;
    while (i < trimmed.len) {
        if (trimmed[i] == '+') {
            // Split on the '+' and recursively parse both sides
            const left_text = std.mem.trim(u8, trimmed[0..i], " \t");
            const right_text = std.mem.trim(u8, trimmed[i + 1 ..], " \t");

            const left = try allocator.create(EvalExpr);
            left.* = try parseExpression(allocator, left_text);

            const right = try allocator.create(EvalExpr);
            right.* = try parseExpression(allocator, right_text);

            return EvalExpr{ .Add = .{ .left = left, .right = right } };
        }
        i += 1;
    }

    // No addition operator found, parse as number
    const num = parseInt(trimmed) catch |err| {
        print("Failed to parse number: {s}\n", .{trimmed});
        return err;
    };

    return EvalExpr{ .Number = num };
}

// Extended command parsing with expressions
fn readCommand(allocator: Allocator) !Command {
    const stdin = std.io.getStdIn().reader();

    while (true) {
        print("> ", .{});

        var input_buffer: [256]u8 = undefined;
        if (stdin.readUntilDelimiterOrEof(&input_buffer, '\n')) |maybe_input| {
            if (maybe_input) |input| {
                const trimmed = std.mem.trim(u8, input, " \t\r\n");

                if (trimmed.len == 0) continue;

                if (std.mem.eql(u8, trimmed, "t")) {
                    return Command.StepInto;
                } else if (std.mem.eql(u8, trimmed, "g")) {
                    return Command.Go;
                } else if (std.mem.eql(u8, trimmed, "r")) {
                    return Command.DisplayRegisters;
                } else if (std.mem.eql(u8, trimmed, "q")) {
                    return Command.Quit;
                } else if (std.mem.startsWith(u8, trimmed, "db ")) {
                    const expr_text = trimmed[3..];
                    var expr = parseExpression(allocator, expr_text) catch {
                        print("Invalid expression in db command\n", .{});
                        continue;
                    };
                    defer expr.deinit(allocator);
                    const addr = expr.evaluate();
                    return Command{ .DisplayBytes = addr };
                } else if (std.mem.startsWith(u8, trimmed, "ln ")) {
                    const expr_text = trimmed[3..];
                    var expr = parseExpression(allocator, expr_text) catch {
                        print("Invalid expression in ln command\n", .{});
                        continue;
                    };
                    defer expr.deinit(allocator);
                    const addr = expr.evaluate();
                    return Command{ .ListNearest = addr };
                } else if (std.mem.startsWith(u8, trimmed, "? ")) {
                    const expr_text = trimmed[2..];
                    var expr = parseExpression(allocator, expr_text) catch {
                        print("Invalid expression in ? command\n", .{});
                        continue;
                    };
                    defer expr.deinit(allocator);
                    const value = expr.evaluate();
                    return Command{ .Evaluate = value };
                } else {
                    print("Unknown command: {s}\n", .{trimmed});
                    print("Available commands:\n", .{});
                    print("  t - step into\n", .{});
                    print("  g - go (continue)\n", .{});
                    print("  r - display registers\n", .{});
                    print("  db <addr> - display bytes at address\n", .{});
                    print("  ln <addr> - list nearest symbol to address\n", .{});
                    print("  ? <expr> - evaluate expression\n", .{});
                    print("  q - quit\n", .{});
                    continue;
                }
            }
        } else |_| {
            // EOF or error
            return Command.Quit;
        }
    }
}

// Read memory from process
fn readProcessMemoryBytes(process: windows.HANDLE, address: u64, buffer: []u8) !usize {
    var bytes_read: usize = 0;
    const result = ReadProcessMemory(
        process,
        @ptrFromInt(address),
        buffer.ptr,
        buffer.len,
        &bytes_read,
    );

    if (result == 0) {
        return error.ReadProcessMemoryFailed;
    }

    return bytes_read;
}

// Read a data structure from process memory
fn readProcessMemoryData(comptime T: type, process: windows.HANDLE, address: u64) !T {
    var data: T = undefined;
    const bytes = std.mem.asBytes(&data);
    const bytes_read = readProcessMemoryBytes(process, address, bytes) catch {
        return error.ReadProcessMemoryFailed;
    };

    if (bytes_read != @sizeOf(T)) {
        return error.IncompleteRead;
    }

    return data;
}

// Read an array from process memory
fn readProcessMemoryArray(comptime T: type, allocator: Allocator, process: windows.HANDLE, address: u64, count: u32) ![]T {
    const array = try allocator.alloc(T, count);
    const bytes = std.mem.sliceAsBytes(array);
    const bytes_read = readProcessMemoryBytes(process, address, bytes) catch {
        allocator.free(array);
        return error.ReadProcessMemoryFailed;
    };

    const expected_size = count * @sizeOf(T);
    if (bytes_read != expected_size) {
        allocator.free(array);
        return error.IncompleteRead;
    }

    return array;
}

// Read a string from process memory
fn readProcessMemoryString(allocator: Allocator, process: windows.HANDLE, address: u64, max_len: usize, is_wide: bool) ![]u8 {
    if (is_wide) {
        // Read as UTF-16 and convert to UTF-8
        const wide_buffer = try allocator.alloc(u16, max_len);
        defer allocator.free(wide_buffer);

        const bytes_buffer = std.mem.sliceAsBytes(wide_buffer);
        const bytes_read = readProcessMemoryBytes(process, address, bytes_buffer) catch {
            return error.ReadProcessMemoryFailed;
        };

        const wide_chars_read = bytes_read / 2;

        // Find null terminator
        var actual_len: usize = 0;
        for (wide_buffer[0..wide_chars_read]) |char| {
            if (char == 0) break;
            actual_len += 1;
        }

        // Convert to UTF-8
        return std.unicode.utf16LeToUtf8Alloc(allocator, wide_buffer[0..actual_len]);
    } else {
        // Read as ASCII/ANSI
        const buffer = try allocator.alloc(u8, max_len);
        const bytes_read = readProcessMemoryBytes(process, address, buffer) catch {
            allocator.free(buffer);
            return error.ReadProcessMemoryFailed;
        };

        // Find null terminator
        var actual_len: usize = 0;
        for (buffer[0..bytes_read]) |char| {
            if (char == 0) break;
            actual_len += 1;
        }

        // Resize to actual length
        return allocator.realloc(buffer, actual_len);
    }
}

// Resolve address to symbol name
fn resolveAddressToName(allocator: Allocator, address: u64, process_info: *Process) !?[]u8 {
    const module = process_info.getContainingModule(address) orelse return null;

    var closest_export: ?*Export = null;
    var closest_addr: u64 = 0;

    // Find the closest export that comes before the address
    for (module.exports.items) |*exp| {
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
            return try std.fmt.allocPrint(allocator, "{s}!{s}+0x{X}", .{ module.name, export_name, offset });
        }
    }

    return null;
}

// Display all registers
fn displayAllRegisters(context: windows.CONTEXT) void {
    print("rax=0x{x:0>16} rbx=0x{x:0>16} rcx=0x{x:0>16}\n", .{ context.Rax, context.Rbx, context.Rcx });
    print("rdx=0x{x:0>16} rsi=0x{x:0>16} rdi=0x{x:0>16}\n", .{ context.Rdx, context.Rsi, context.Rdi });
    print("rip=0x{x:0>16} rsp=0x{x:0>16} rbp=0x{x:0>16}\n", .{ context.Rip, context.Rsp, context.Rbp });
    print(" r8=0x{x:0>16}  r9=0x{x:0>16} r10=0x{x:0>16}\n", .{ context.R8, context.R9, context.R10 });
    print("r11=0x{x:0>16} r12=0x{x:0>16} r13=0x{x:0>16}\n", .{ context.R11, context.R12, context.R13 });
    print("r14=0x{x:0>16} r15=0x{x:0>16} eflags=0x{x:0>8}\n", .{ context.R14, context.R15, context.EFlags });
}

// Display bytes at a memory address
fn displayBytes(process: windows.HANDLE, address: u64) void {
    var buffer: [16]u8 = undefined;
    const bytes_read = readProcessMemoryBytes(process, address, &buffer) catch |err| {
        print("ReadProcessMemory failed: {any}\n", .{err});
        return;
    };

    print("{x:0>8}: ", .{@as(u32, @truncate(address))});
    for (0..bytes_read) |i| {
        print("{x:0>2} ", .{buffer[i]});
    }
    print("\n", .{});
}

fn mainDebuggerLoop(allocator: Allocator, process: windows.HANDLE) !void {
    var expect_step_exception = false;
    var process_info = Process.init(allocator);
    defer process_info.deinit(allocator);

    while (true) {
        var debug_event = std.mem.zeroes(DEBUG_EVENT);

        const wait_result = WaitForDebugEventEx(&debug_event, INFINITE);
        if (wait_result == 0) {
            print("WaitForDebugEventEx failed\n", .{});
            break;
        }

        var continue_status: windows.DWORD = DBG_CONTINUE;

        switch (debug_event.dwDebugEventCode) {
            EXCEPTION_DEBUG_EVENT => {
                const code = debug_event.u.Exception.ExceptionRecord.ExceptionCode;
                const first_chance = debug_event.u.Exception.dwFirstChance;
                const chance_string = if (first_chance == 0) "second chance" else "first chance";

                if (expect_step_exception and code == EXCEPTION_SINGLE_STEP) {
                    expect_step_exception = false;
                    continue_status = DBG_CONTINUE;
                } else {
                    print("Exception code {x} ({s})\n", .{ code, chance_string });
                    continue_status = DBG_EXCEPTION_NOT_HANDLED;
                }
            },
            CREATE_THREAD_DEBUG_EVENT => print("CreateThread\n", .{}),
            CREATE_PROCESS_DEBUG_EVENT => {
                const create_process = debug_event.u.CreateProcessInfo;
                const dll_base = @intFromPtr(create_process.lpBaseOfImage);

                // Get process name from image
                var process_name: ?[]u8 = null;
                defer if (process_name) |name| allocator.free(name);

                if (create_process.lpImageName != null) {
                    const dll_name_address = readProcessMemoryData(u64, process, @intFromPtr(create_process.lpImageName)) catch 0;

                    if (dll_name_address != 0) {
                        const is_wide = create_process.fUnicode != 0;
                        process_name = readProcessMemoryString(allocator, process, dll_name_address, MAX_PATH, is_wide) catch null;
                    }
                }

                _ = process_info.addModule(allocator, dll_base, process_name, process) catch |err| {
                    print("Failed to add process module: {any}\n", .{err});
                };

                if (process_name) |name| {
                    print("CreateProcess\nLoadDll: {x} {s}\n", .{ dll_base, name });
                } else {
                    print("CreateProcess\nLoadDll: {x}\n", .{dll_base});
                }
            },
            EXIT_THREAD_DEBUG_EVENT => print("ExitThread\n", .{}),
            EXIT_PROCESS_DEBUG_EVENT => print("ExitProcess\n", .{}),
            LOAD_DLL_DEBUG_EVENT => {
                const load_dll = debug_event.u.LoadDll;
                const dll_base = @intFromPtr(load_dll.lpBaseOfDll);

                var dll_name: ?[]u8 = null;
                defer if (dll_name) |name| allocator.free(name);

                if (load_dll.lpImageName != null) {
                    // Read the pointer to the name string
                    const dll_name_address = readProcessMemoryData(u64, process, @intFromPtr(load_dll.lpImageName)) catch 0;

                    if (dll_name_address != 0) {
                        const is_wide = load_dll.fUnicode != 0;
                        dll_name = readProcessMemoryString(allocator, process, dll_name_address, MAX_PATH, is_wide) catch null;
                    }
                }

                _ = process_info.addModule(allocator, dll_base, dll_name, process) catch |err| {
                    print("Failed to add module: {any}\n", .{err});
                };

                if (dll_name) |name| {
                    print("LoadDll: {x} {s}\n", .{ dll_base, name });
                } else {
                    print("LoadDll: {x}\n", .{dll_base});
                }
            },
            UNLOAD_DLL_DEBUG_EVENT => print("UnloadDll\n", .{}),
            OUTPUT_DEBUG_STRING_EVENT => {
                const debug_string_info = debug_event.u.DebugString;
                const is_wide = debug_string_info.fUnicode != 0;
                const address = @intFromPtr(debug_string_info.lpDebugStringData);
                const len = debug_string_info.nDebugStringLength;

                const debug_string = readProcessMemoryString(allocator, process, address, len, is_wide) catch {
                    print("DebugOut: <failed to read string>\n", .{});
                    continue;
                };
                defer allocator.free(debug_string);

                print("DebugOut: {s}\n", .{debug_string});
            },
            RIP_EVENT => print("RipEvent\n", .{}),
            else => {
                print("Unexpected debug event: {}\n", .{debug_event.dwDebugEventCode});
                break;
            },
        }

        // Open thread handle for reading/writing context
        var thread = AutoClosedHandle.init(OpenThread(
            THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
            FALSE,
            debug_event.dwThreadId,
        ));
        defer thread.deinit();

        if (thread.getHandle() == windows.INVALID_HANDLE_VALUE) {
            print("Failed to open thread\n", .{});
            continue;
        }

        // Get thread context
        var ctx = AlignedContext.init();
        ctx.context.ContextFlags = CONTEXT_ALL;

        const get_context_result = GetThreadContext(thread.getHandle(), &ctx.context);
        if (get_context_result == 0) {
            print("GetThreadContext failed\n", .{});
            continue;
        }

        var continue_execution = false;

        while (!continue_execution) {
            // Try to resolve the instruction pointer to a symbol
            if (resolveAddressToName(allocator, ctx.context.Rip, &process_info)) |opSym| {
                if (opSym) |sym| {
                    print("[{x}] {s}\n", .{ debug_event.dwThreadId, sym });
                    allocator.free(sym);
                }
            } else |_| {
                print("[{x}] 0x{x:0>16}\n", .{ debug_event.dwThreadId, ctx.context.Rip });
            }

            const cmd = readCommand(allocator) catch |err| {
                print("Command parsing error: {any}\n", .{err});
                continue;
            };

            switch (cmd) {
                Command.StepInto => {
                    ctx.context.EFlags |= TRAP_FLAG;
                    const set_context_result = SetThreadContext(thread.getHandle(), &ctx.context);
                    if (set_context_result == 0) {
                        print("SetThreadContext failed\n", .{});
                        continue;
                    }
                    expect_step_exception = true;
                    continue_execution = true;
                },
                Command.Go => {
                    continue_execution = true;
                },
                Command.DisplayRegisters => {
                    displayAllRegisters(ctx.context);
                },
                Command.DisplayBytes => |address| {
                    displayBytes(process, address);
                },
                Command.ListNearest => |address| {
                    if (resolveAddressToName(allocator, address, &process_info)) |opSym| {
                        if (opSym) |sym| {
                            print("{s}\n", .{sym});
                            allocator.free(sym);
                        }
                    } else |_| {
                        print("No symbol found\n", .{});
                    }
                },
                Command.Evaluate => |value| {
                    print(" = 0x{x}\n", .{value});
                },
                Command.Quit => {
                    // The process will be terminated since we didn't detach
                    return;
                },
                Command.Unknown => {
                    // This shouldn't happen with our current implementation
                    continue;
                },
            }
        }

        if (debug_event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            break;
        }

        _ = ContinueDebugEvent(
            debug_event.dwProcessId,
            debug_event.dwThreadId,
            continue_status,
        );
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const target_command_line = parseCommandLine(allocator) catch |err| {
        const error_msg = switch (err) {
            error.EmptyCommandLine => "Command line was empty",
            error.NoArgumentsFound => "No arguments found",
            error.OutOfMemory => "Out of memory",
        };
        showUsage(error_msg);
        return;
    };
    defer allocator.free(target_command_line);

    // Convert to UTF-8 for display
    const utf8_cmd_line = std.unicode.utf16LeToUtf8Alloc(allocator, target_command_line[0 .. target_command_line.len - 1]) catch |err| {
        print("Failed to convert command line to UTF-8: {any}\n", .{err});
        return;
    };
    defer allocator.free(utf8_cmd_line);

    print("Command line was: '{s}'\n", .{utf8_cmd_line});

    var si = std.mem.zeroes(STARTUPINFOEXW);
    si.StartupInfo.cb = @sizeOf(STARTUPINFOEXW);
    var pi = std.mem.zeroes(PROCESS_INFORMATION);

    const create_result = CreateProcessW(
        null, // lpApplicationName
        @ptrCast(target_command_line.ptr), // lpCommandLine (mutable)
        null, // lpProcessAttributes
        null, // lpThreadAttributes
        FALSE, // bInheritHandles
        DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE, // dwCreationFlags
        null, // lpEnvironment
        null, // lpCurrentDirectory
        &si.StartupInfo, // lpStartupInfo
        &pi, // lpProcessInformation
    );

    if (create_result == 0) {
        const err = windows.kernel32.GetLastError();
        print("CreateProcessW failed with error: {}\n", .{err});
        return;
    }

    // Close the thread handle as we don't need it
    _ = CloseHandle(pi.hThread);

    // Run the main debugger loop
    try mainDebuggerLoop(allocator, pi.hProcess);

    // Clean up
    _ = CloseHandle(pi.hProcess);
}
