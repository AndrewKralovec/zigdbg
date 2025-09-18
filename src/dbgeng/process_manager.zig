//! Process management using DbgEng API
//! This module provides process creation, attachment, and dump file debugging capabilities
//! to replace the Win32 CreateProcessW approach with modern DbgEng APIs.

const std = @import("std");
const windows = std.os.windows;
const com_interfaces = @import("com_interfaces.zig");
const event_callbacks = @import("event_callbacks.zig");
const com_utils = @import("com_utils.zig");

const HRESULT = com_interfaces.HRESULT;
const ULONG = com_interfaces.ULONG;
const IDebugClient5 = com_interfaces.IDebugClient5;
const IDebugControl4 = com_interfaces.IDebugControl4;
const DebugEventCallbacks = event_callbacks.DebugEventCallbacks;

pub const ProcessManagerError = error{
    ProcessCreationFailed,
    ProcessAttachmentFailed,
    DumpFileOpenFailed,
    CallbackRegistrationFailed,
    InvalidProcessId,
    InvalidExecutablePath,
    OutOfMemory,
};

pub const ProcessManager = struct {
    allocator: std.mem.Allocator,
    debug_client: ?*IDebugClient5,
    debug_control: ?*IDebugControl4,
    event_callbacks: ?*DebugEventCallbacks,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .debug_client = null,
            .debug_control = null,
            .event_callbacks = null,
        };
    }

    pub fn deinit(self: *Self) void {
        // Release event_callbacks since we created them
        if (self.event_callbacks) |callbacks| {
            _ = callbacks.vtbl.Release(@ptrCast(callbacks));
            self.event_callbacks = null;
        }

        // Release our AddRef'd references to the interfaces
        if (self.debug_control) |control| {
            _ = control.release();
            self.debug_control = null;
        }
        if (self.debug_client) |client| {
            _ = client.release();
            self.debug_client = null;
        }
    }

    pub fn setInterfaces(self: *Self, debug_client: *IDebugClient5, debug_control: *IDebugControl4) !void {
        // Store references and AddRef them since we're keeping them
        self.debug_client = debug_client;
        self.debug_control = debug_control;

        // AddRef the interfaces since we're storing references to them
        _ = debug_client.addRef();
        _ = debug_control.addRef();

        // Create and register event callbacks
        self.event_callbacks = try DebugEventCallbacks.create(self.allocator);
        const hr = debug_client.vtbl.SetEventCallbacks(debug_client, @ptrCast(self.event_callbacks));
        if (com_utils.failed(hr)) {
            return ProcessManagerError.CallbackRegistrationFailed;
        }
    }

    /// Create a new process for debugging using IDebugClient::CreateProcess
    /// This replaces the Win32 CreateProcessW approach
    pub fn createProcess(self: *Self, command_line: []const u8) !void {
        if (self.debug_client == null) return ProcessManagerError.ProcessCreationFailed;

        // Convert UTF-8 command line to wide string
        var wide_command_line: [1024:0]u16 = undefined;
        const wide_len = try std.unicode.utf8ToUtf16Le(wide_command_line[0..], command_line);
        wide_command_line[wide_len] = 0;

        // Create process with debug flags
        const create_flags = com_interfaces.DEBUG_PROCESS_ONLY_THIS_PROCESS |
            com_interfaces.DEBUG_CREATE_PROCESS_NO_DEBUG_HEAP;

        const hr = self.debug_client.?.vtbl.CreateProcess(
            self.debug_client.?,
            null, // Use default server
            @ptrCast(&wide_command_line),
            create_flags,
        );

        if (com_utils.failed(hr)) {
            std.debug.print("Failed to create process: HRESULT = 0x{X}\n", .{hr});
            return ProcessManagerError.ProcessCreationFailed;
        }

        std.debug.print("Process created successfully: {s}\n", .{command_line});
    }

    /// Attach to an existing process by PID
    pub fn attachToProcess(self: *Self, process_id: u32) !void {
        if (self.debug_client == null) return ProcessManagerError.ProcessAttachmentFailed;

        // Attach to the process
        const hr = self.debug_client.?.vtbl.AttachProcess(
            self.debug_client.?,
            null, // Use default server
            process_id,
            0, // Default attach flags
        );

        if (com_utils.failed(hr)) {
            std.debug.print("Failed to attach to process {}: HRESULT = 0x{X}\n", .{ process_id, hr });
            return ProcessManagerError.ProcessAttachmentFailed;
        }

        std.debug.print("Successfully attached to process: {}\n", .{process_id});
    }

    /// Attach to an existing process by executable name
    pub fn attachToProcessByName(self: *Self, executable_name: []const u8) !void {
        if (self.debug_client == null) return ProcessManagerError.ProcessAttachmentFailed;

        // Get running process IDs
        var process_ids: [256]ULONG = undefined;
        var actual_count: ULONG = 0;

        const hr = self.debug_client.?.vtbl.GetRunningProcessSystemIds(
            self.debug_client.?,
            null, // Use default server
            @ptrCast(&process_ids[0]),
            process_ids.len,
            &actual_count,
        );

        if (com_utils.failed(hr)) {
            std.debug.print("Failed to get running processes: HRESULT = 0x{X}\n", .{hr});
            return ProcessManagerError.ProcessAttachmentFailed;
        }

        // Find process by executable name
        var exe_name_buf: [512]u8 = undefined;
        var image_name_buf: [512]u8 = undefined;

        for (process_ids[0..actual_count]) |pid| {
            var exe_name_size: ULONG = 0;
            var image_name_size: ULONG = 0;

            const desc_hr = self.debug_client.?.vtbl.GetRunningProcessDescription(
                self.debug_client.?,
                null, // Use default server
                pid,
                0, // Default flags
                &exe_name_buf,
                exe_name_buf.len,
                &exe_name_size,
                &image_name_buf,
                image_name_buf.len,
                &image_name_size,
            );

            if (com_utils.succeeded(desc_hr)) {
                const exe_name = if (exe_name_size > 0) exe_name_buf[0..exe_name_size] else "";
                if (std.mem.indexOf(u8, exe_name, executable_name) != null) {
                    std.debug.print("Found process '{s}' with PID: {}\n", .{ exe_name, pid });
                    return self.attachToProcess(pid);
                }
            }
        }

        std.debug.print("Process '{s}' not found\n", .{executable_name});
        return ProcessManagerError.ProcessAttachmentFailed;
    }

    /// Open a dump file for analysis
    pub fn openDumpFile(self: *Self, dump_file_path: []const u8) !void {
        if (self.debug_client == null) return ProcessManagerError.DumpFileOpenFailed;

        // Convert UTF-8 path to null-terminated string
        var path_buffer: [1024:0]u8 = undefined;
        if (dump_file_path.len >= path_buffer.len) {
            return ProcessManagerError.InvalidExecutablePath;
        }
        @memcpy(path_buffer[0..dump_file_path.len], dump_file_path);
        path_buffer[dump_file_path.len] = 0;

        const hr = self.debug_client.?.vtbl.OpenDumpFile(
            self.debug_client.?,
            @ptrCast(&path_buffer),
        );

        if (com_utils.failed(hr)) {
            std.debug.print("Failed to open dump file '{s}': HRESULT = 0x{X}\n", .{ dump_file_path, hr });
            return ProcessManagerError.DumpFileOpenFailed;
        }

        std.debug.print("Dump file opened successfully: {s}\n", .{dump_file_path});
    }

    /// Wait for debug events and dispatch them to our callbacks
    /// This replaces the WaitForDebugEventEx loop
    pub fn waitForEvents(self: *Self, timeout_ms: u32) !bool {
        if (self.debug_client == null) return false;

        const hr = self.debug_client.?.vtbl.DispatchCallbacks(
            self.debug_client.?,
            timeout_ms,
        );

        return com_utils.succeeded(hr);
    }

    /// Start the debug session - this initiates the callback-driven event model
    pub fn startSession(self: *Self) !void {
        if (self.debug_control == null) return ProcessManagerError.ProcessCreationFailed;

        // Set execution status to GO to start the debuggee
        const hr = self.debug_control.?.vtbl.SetExecutionStatus(
            self.debug_control.?,
            com_interfaces.DEBUG_STATUS_GO,
        );

        if (com_utils.failed(hr)) {
            std.debug.print("Failed to start execution: HRESULT = 0x{X}\n", .{hr});
            return ProcessManagerError.ProcessCreationFailed;
        }

        std.debug.print("Debug session started - event callbacks are now active\n", .{});
    }

    /// Stop the debug session
    pub fn stopSession(self: *Self) !void {
        if (self.debug_control == null) return;

        // Set execution status to BREAK to stop the debuggee
        const hr = self.debug_control.?.vtbl.SetExecutionStatus(
            self.debug_control.?,
            com_interfaces.DEBUG_STATUS_BREAK,
        );

        if (com_utils.failed(hr)) {
            std.debug.print("Failed to break execution: HRESULT = 0x{X}\n", .{hr});
        } else {
            std.debug.print("Debug session stopped\n", .{});
        }
    }

    /// Detach from the current process
    pub fn detachProcess(self: *Self) !void {
        if (self.debug_client == null) return;

        const hr = self.debug_client.?.vtbl.DetachProcesses(self.debug_client.?);

        if (com_utils.failed(hr)) {
            std.debug.print("Failed to detach from process: HRESULT = 0x{X}\n", .{hr});
        } else {
            std.debug.print("Detached from process\n", .{});
        }
    }

    /// Terminate the current process
    pub fn terminateProcess(self: *Self) !void {
        if (self.debug_client == null) return;

        const hr = self.debug_client.?.vtbl.TerminateProcesses(self.debug_client.?);

        if (com_utils.failed(hr)) {
            std.debug.print("Failed to terminate process: HRESULT = 0x{X}\n", .{hr});
        } else {
            std.debug.print("Process terminated\n", .{});
        }
    }
};
