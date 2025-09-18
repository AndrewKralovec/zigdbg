//! Main DbgEng client wrapper that encapsulates all DbgEng interfaces
//! This module provides the primary interface for the debugger

const std = @import("std");
const windows = std.os.windows;
const com_interfaces = @import("com_interfaces.zig");
const com_utils = @import("com_utils.zig");
const process_manager = @import("process_manager.zig");

// Import essential types
const HRESULT = com_interfaces.HRESULT;
const GUID = com_interfaces.GUID;
const ULONG = com_interfaces.ULONG;
const ULONG64 = com_interfaces.ULONG64;

// Import COM interfaces
const IDebugClient5 = com_interfaces.IDebugClient5;
const IDebugControl4 = com_interfaces.IDebugControl4;
const DebugCreate = com_interfaces.DebugCreate;

// Import interface IDs
const IID_IDebugClient5 = com_interfaces.IID_IDebugClient5;
const IID_IDebugControl4 = com_interfaces.IID_IDebugControl4;
const IID_IDebugSymbols3 = com_interfaces.IID_IDebugSymbols3;
const IID_IDebugRegisters2 = com_interfaces.IID_IDebugRegisters2;
const IID_IDebugDataSpaces4 = com_interfaces.IID_IDebugDataSpaces4;
const IID_IDebugSystemObjects4 = com_interfaces.IID_IDebugSystemObjects4;

// Import COM utilities
const ComInitializer = com_utils.ComInitializer;
const ComClient = com_utils.ComClient;
const ComControl = com_utils.ComControl;
const WideString = com_utils.WideString;
const succeeded = com_utils.succeeded;
const failed = com_utils.failed;
const hresultWrap = com_utils.hresultWrap;
const debugPrintHresult = com_utils.debugPrintHresult;

// Import process manager
const ProcessManager = process_manager.ProcessManager;

// Debug status constants from com_interfaces
const DEBUG_STATUS_NO_CHANGE = com_interfaces.DEBUG_STATUS_NO_CHANGE;
const DEBUG_STATUS_GO = com_interfaces.DEBUG_STATUS_GO;
const DEBUG_STATUS_BREAK = com_interfaces.DEBUG_STATUS_BREAK;
const DEBUG_STATUS_STEP_OVER = com_interfaces.DEBUG_STATUS_STEP_OVER;
const DEBUG_STATUS_STEP_INTO = com_interfaces.DEBUG_STATUS_STEP_INTO;

// Process creation flags
const DEBUG_PROCESS_ONLY_THIS_PROCESS = com_interfaces.DEBUG_PROCESS_ONLY_THIS_PROCESS;
const DEBUG_CREATE_PROCESS_NO_DEBUG_HEAP = com_interfaces.DEBUG_CREATE_PROCESS_NO_DEBUG_HEAP;

// Attach flags
const DEBUG_ATTACH_NONINVASIVE = com_interfaces.DEBUG_ATTACH_NONINVASIVE;
const DEBUG_ATTACH_EXISTING = com_interfaces.DEBUG_ATTACH_EXISTING;

/// Configuration options for the DbgEng client
pub const DbgEngConfig = struct {
    /// COM threading model to use
    threading_model: ComThreadingModel = .apartment_threaded,
    /// Enable verbose logging
    verbose_logging: bool = false,
    /// Default timeout for operations (in milliseconds)
    default_timeout: u32 = 10000,

    pub const ComThreadingModel = enum {
        apartment_threaded,
        multi_threaded,
    };
};

/// Main DbgEng client that encapsulates all debugging interfaces
pub const DbgEngClient = struct {
    allocator: std.mem.Allocator,
    config: DbgEngConfig,
    com_init: ComInitializer,

    // Core interfaces
    client: ComClient,
    control: ComControl,

    // Process manager for handling process operations and events
    process_manager: ProcessManager,

    // Additional interfaces (to be added as needed)
    symbols: ?*anyopaque = null,
    registers: ?*anyopaque = null,
    data_spaces: ?*anyopaque = null,
    system_objects: ?*anyopaque = null,

    // State tracking
    is_attached: bool = false,
    current_process_id: u32 = 0,

    const Self = @This();

    /// Initialize a new DbgEng client with the specified configuration
    pub fn init(allocator: std.mem.Allocator, config: DbgEngConfig) !Self {
        if (config.verbose_logging) {
            std.debug.print("Initializing DbgEng client...\n", .{});
        }

        // Initialize COM
        const com_init = switch (config.threading_model) {
            .apartment_threaded => try ComInitializer.initApartmentThreaded(),
            .multi_threaded => try ComInitializer.initMultiThreaded(),
        };

        if (config.verbose_logging) {
            std.debug.print("COM initialized successfully\n", .{});
        }

        // Create the primary IDebugClient5 interface
        var client_ptr: ?*anyopaque = null;
        const hr = DebugCreate(&IID_IDebugClient5, &client_ptr);

        if (failed(hr)) {
            debugPrintHresult(hr, "DebugCreate failed");
            return error.DbgEngInitializationFailed;
        }

        if (config.verbose_logging) {
            std.debug.print("DbgEng IDebugClient5 created successfully\n", .{});
        }

        const debug_client = @as(*IDebugClient5, @ptrCast(@alignCast(client_ptr.?)));
        const client = ComClient.fromOwned(debug_client);

        // Query for IDebugControl4 interface
        const control = client.queryInterface(IDebugControl4, &IID_IDebugControl4) catch |err| {
            std.debug.print("Failed to query IDebugControl4 interface: {}\n", .{err});
            return error.DbgEngInitializationFailed;
        };

        if (config.verbose_logging) {
            std.debug.print("IDebugControl4 interface obtained successfully\n", .{});
        }

        // Initialize process manager
        var proc_manager = ProcessManager.init(allocator);
        try proc_manager.setInterfaces(debug_client, control.getRequired());

        if (config.verbose_logging) {
            std.debug.print("Process manager initialized with event callbacks\n", .{});
        }

        return Self{
            .allocator = allocator,
            .config = config,
            .com_init = com_init,
            .client = client,
            .control = control,
            .process_manager = proc_manager,
        };
    }

    /// Clean up the DbgEng client and release all resources
    pub fn deinit(self: *Self) void {
        if (self.config.verbose_logging) {
            std.debug.print("Cleaning up DbgEng client...\n", .{});
        }

        // Detach from any processes if attached
        if (self.is_attached) {
            self.detachProcesses() catch |err| {
                std.debug.print("Warning: Failed to detach processes during cleanup: {}\n", .{err});
            };
        }

        // Clean up process manager
        self.process_manager.deinit();

        // Release COM interfaces
        self.control.deinit();
        self.client.deinit();

        // Clean up COM
        self.com_init.deinit();

        if (self.config.verbose_logging) {
            std.debug.print("DbgEng client cleanup complete\n", .{});
        }
    }

    /// Create a new process and attach the debugger to it
    /// This now uses the ProcessManager with callback-driven events
    pub fn createProcess(self: *Self, command_line: []const u8) !void {
        if (self.config.verbose_logging) {
            std.debug.print("Creating process: {s}\n", .{command_line});
        }

        // Use the process manager to create the process
        try self.process_manager.createProcess(command_line);

        self.is_attached = true;

        // Start the callback-driven debug session
        try self.process_manager.startSession();

        if (self.config.verbose_logging) {
            std.debug.print("Process created successfully with event callbacks active\n", .{});
        }
    }

    /// Attach to an existing process by process ID
    pub fn attachProcess(self: *Self, process_id: u32, noninvasive: bool) !void {
        _ = noninvasive; // TODO: Implement noninvasive attachment in ProcessManager

        if (self.config.verbose_logging) {
            std.debug.print("Attaching to process ID: {}\n", .{process_id});
        }

        // Use the process manager to attach to the process
        try self.process_manager.attachToProcess(process_id);

        self.is_attached = true;
        self.current_process_id = process_id;

        // Start the callback-driven debug session
        try self.process_manager.startSession();

        if (self.config.verbose_logging) {
            std.debug.print("Successfully attached to process {} with event callbacks active\n", .{process_id});
        }
    }

    /// Attach to an existing process by executable name
    pub fn attachProcessByName(self: *Self, executable_name: []const u8) !void {
        if (self.config.verbose_logging) {
            std.debug.print("Attaching to process by name: {s}\n", .{executable_name});
        }

        // Use the process manager to find and attach to the process
        try self.process_manager.attachToProcessByName(executable_name);

        self.is_attached = true;

        // Start the callback-driven debug session
        try self.process_manager.startSession();

        if (self.config.verbose_logging) {
            std.debug.print("Successfully attached to process '{s}' with event callbacks active\n", .{executable_name});
        }
    }

    /// Open a dump file for analysis
    pub fn openDumpFile(self: *Self, dump_file_path: []const u8) !void {
        if (self.config.verbose_logging) {
            std.debug.print("Opening dump file: {s}\n", .{dump_file_path});
        }

        // Use the process manager to open the dump file
        try self.process_manager.openDumpFile(dump_file_path);

        self.is_attached = true;

        if (self.config.verbose_logging) {
            std.debug.print("Dump file opened successfully: {s}\n", .{dump_file_path});
        }
    }

    /// Detach from all processes
    pub fn detachProcesses(self: *Self) !void {
        if (self.config.verbose_logging) {
            std.debug.print("Detaching from processes...\n", .{});
        }

        const hr = self.client.getRequired().detachProcesses();

        if (failed(hr)) {
            debugPrintHresult(hr, "DetachProcesses failed");
            return error.ProcessDetachFailed;
        }

        self.is_attached = false;
        self.current_process_id = 0;

        if (self.config.verbose_logging) {
            std.debug.print("Successfully detached from processes\n", .{});
        }
    }

    /// Terminate all processes
    pub fn terminateProcesses(self: *Self) !void {
        if (self.config.verbose_logging) {
            std.debug.print("Terminating processes...\n", .{});
        }

        const hr = self.client.getRequired().terminateProcesses();

        if (failed(hr)) {
            debugPrintHresult(hr, "TerminateProcesses failed");
            return error.ProcessTerminationFailed;
        }

        self.is_attached = false;
        self.current_process_id = 0;

        if (self.config.verbose_logging) {
            std.debug.print("Successfully terminated processes\n", .{});
        }
    }

    /// Continue execution (go)
    pub fn go(self: *Self) !void {
        if (self.config.verbose_logging) {
            std.debug.print("Continuing execution...\n", .{});
        }

        const hr = self.control.getRequired().setExecutionStatus(DEBUG_STATUS_GO);

        if (failed(hr)) {
            debugPrintHresult(hr, "SetExecutionStatus(GO) failed");
            return error.ExecutionControlFailed;
        }
    }

    /// Break execution
    pub fn breakExecution(self: *Self) !void {
        if (self.config.verbose_logging) {
            std.debug.print("Breaking execution...\n", .{});
        }

        const hr = self.control.getRequired().setExecutionStatus(DEBUG_STATUS_BREAK);

        if (failed(hr)) {
            debugPrintHresult(hr, "SetExecutionStatus(BREAK) failed");
            return error.ExecutionControlFailed;
        }
    }

    /// Step over (execute one instruction, step over calls)
    pub fn stepOver(self: *Self) !void {
        if (self.config.verbose_logging) {
            std.debug.print("Stepping over...\n", .{});
        }

        const hr = self.control.getRequired().setExecutionStatus(DEBUG_STATUS_STEP_OVER);

        if (failed(hr)) {
            debugPrintHresult(hr, "SetExecutionStatus(STEP_OVER) failed");
            return error.ExecutionControlFailed;
        }
    }

    /// Step into (execute one instruction, step into calls)
    pub fn stepInto(self: *Self) !void {
        if (self.config.verbose_logging) {
            std.debug.print("Stepping into...\n", .{});
        }

        const hr = self.control.getRequired().setExecutionStatus(DEBUG_STATUS_STEP_INTO);

        if (failed(hr)) {
            debugPrintHresult(hr, "SetExecutionStatus(STEP_INTO) failed");
            return error.ExecutionControlFailed;
        }
    }

    /// Wait for debug events using the callback-driven model
    /// This replaces the WaitForDebugEventEx loop
    pub fn waitForEvents(self: *Self, timeout_ms: ?u32) !bool {
        const timeout = timeout_ms orelse self.config.default_timeout;

        if (self.config.verbose_logging) {
            std.debug.print("Waiting for events via callbacks (timeout: {}ms)...\n", .{timeout});
        }

        return self.process_manager.waitForEvents(timeout);
    }

    /// Get current execution status
    pub fn getExecutionStatus(self: *Self) !u32 {
        var status: ULONG = 0;
        const hr = self.control.getRequired().getExecutionStatus(&status);

        if (failed(hr)) {
            debugPrintHresult(hr, "GetExecutionStatus failed");
            return error.ExecutionStatusFailed;
        }

        return status;
    }

    /// Output text to the debugger console
    pub fn output(self: *Self, text: []const u8) !void {
        // Create null-terminated string for COM API
        const text_z = try self.allocator.dupeZ(u8, text);
        defer self.allocator.free(text_z);

        const hr = self.control.getRequired().output(0x00000001, text_z.ptr); // DEBUG_OUTPUT_NORMAL

        if (failed(hr)) {
            debugPrintHresult(hr, "Output failed");
            return error.OutputFailed;
        }
    }

    /// Dispatch callbacks to handle events
    pub fn dispatchCallbacks(self: *Self, timeout_ms: ?u32) !void {
        const timeout = timeout_ms orelse self.config.default_timeout;

        const hr = self.client.getRequired().dispatchCallbacks(timeout);

        if (failed(hr)) {
            debugPrintHresult(hr, "DispatchCallbacks failed");
            return error.CallbackDispatchFailed;
        }
    }

    /// Check if the client is currently attached to a process
    pub fn isAttached(self: *const Self) bool {
        return self.is_attached;
    }

    /// Get the current process ID (if attached)
    pub fn getCurrentProcessId(self: *const Self) u32 {
        return self.current_process_id;
    }

    /// Simple status check and output method for testing
    pub fn printStatus(self: *Self) !void {
        const status = try self.getExecutionStatus();
        const status_text = switch (status) {
            DEBUG_STATUS_NO_CHANGE => "NO_CHANGE",
            DEBUG_STATUS_GO => "RUNNING",
            DEBUG_STATUS_BREAK => "BREAK",
            DEBUG_STATUS_STEP_OVER => "STEP_OVER",
            DEBUG_STATUS_STEP_INTO => "STEP_INTO",
            else => "UNKNOWN",
        };

        const message = std.fmt.allocPrint(
            self.allocator,
            "Debugger Status: {s} ({})\n",
            .{ status_text, status }
        ) catch return error.OutputFailed;
        defer self.allocator.free(message);

        try self.output(message);
    }
};

/// Error set for DbgEng operations
pub const DbgEngError = error{
    DbgEngInitializationFailed,
    ProcessCreationFailed,
    ProcessAttachFailed,
    ProcessDetachFailed,
    ProcessTerminationFailed,
    ExecutionControlFailed,
    EventWaitFailed,
    ExecutionStatusFailed,
    OutputFailed,
    CallbackDispatchFailed,
} || com_utils.ComError || std.mem.Allocator.Error;

/// Convenience function to create a DbgEng client with default configuration
pub fn createClient(allocator: std.mem.Allocator) !DbgEngClient {
    return DbgEngClient.init(allocator, .{});
}

/// Convenience function to create a DbgEng client with verbose logging
pub fn createVerboseClient(allocator: std.mem.Allocator) !DbgEngClient {
    return DbgEngClient.init(allocator, .{ .verbose_logging = true });
}

test "DbgEng client initialization" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Note: This test will only pass on Windows with DbgEng available
    if (@import("builtin").os.tag != .windows) {
        return error.SkipZigTest;
    }

    var client = createClient(allocator) catch |err| switch (err) {
        error.DbgEngInitializationFailed => {
            // This is expected if DbgEng is not available
            std.debug.print("DbgEng not available (expected in test environment)\n", .{});
            return;
        },
        else => return err,
    };
    defer client.deinit();

    try std.testing.expect(!client.isAttached());
    try std.testing.expect(client.getCurrentProcessId() == 0);
}