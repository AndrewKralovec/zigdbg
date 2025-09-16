const std = @import("std");
const windows = std.os.windows;
const print = std.debug.print;
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;

const memory = @import("memory.zig");
const util = @import("util.zig");
const Module = @import("module.zig").Module;

// Process structure to track modules and threads
pub const Process = struct {
    modules: ArrayList(Module),
    thread_ids: ArrayList(u32),

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .modules = ArrayList(Module).init(allocator),
            .thread_ids = ArrayList(u32).init(allocator),
        };
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        for (self.modules.items) |*mod| {
            mod.deinit(allocator);
        }
        self.modules.deinit();
        self.thread_ids.deinit();
    }

    pub fn addModule(self: *Self, allocator: Allocator, address: u64, name: ?[]const u8, process: windows.HANDLE) !*Module {
        const new_module = Module.init(allocator, address, name, process) catch |err| {
            print("Failed to create module: {any}\n", .{err});
            return err;
        };

        try self.modules.append(new_module);
        return &self.modules.items[self.modules.items.len - 1];
    }

    pub fn addThread(self: *Self, thread_id: u32) !void {
        try self.thread_ids.append(thread_id);
    }

    pub fn removeThread(self: *Self, thread_id: u32) void {
        var i: usize = 0;
        while (i < self.thread_ids.items.len) {
            if (self.thread_ids.items[i] == thread_id) {
                _ = self.thread_ids.orderedRemove(i);
                return;
            }
            i += 1;
        }
    }

    pub fn getContainingModule(self: *Self, address: u64) ?*Module {
        for (self.modules.items) |*mod| {
            if (mod.containsAddress(address)) {
                return mod;
            }
        }
        return null;
    }

    pub fn getModuleByName(self: *Self, name: []const u8) ?*Module {
        const filename = util.extractFilename(name);
        for (self.modules.items) |*mod| {
            if (std.mem.eql(u8, mod.name, filename)) {
                return mod;
            }
        }
        return null;
    }
};
