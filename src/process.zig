const std = @import("std");
const Module = @import("module.zig").Module;
const memory = @import("memory.zig");

pub const Process = struct {
    module_list: std.ArrayList(Module),
    thread_list: std.ArrayList(u32),
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) Process {
        return Process{
            .module_list = std.ArrayList(Module).init(allocator),
            .thread_list = std.ArrayList(u32).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *Process) void {
        // Clean up all modules
        for (self.module_list.items) |*module| {
            module.deinit();
        }
        self.module_list.deinit();
        self.thread_list.deinit();
    }
    
    pub fn addModule(self: *Process, address: u64, name: ?[]const u8, mem_source: memory.MemorySource) !*Module {
        const module = try Module.init(self.allocator, address, name, mem_source);
        try self.module_list.append(module);
        return &self.module_list.items[self.module_list.items.len - 1];
    }
    
    pub fn addThread(self: *Process, thread_id: u32) !void {
        try self.thread_list.append(thread_id);
    }
    
    pub fn removeThread(self: *Process, thread_id: u32) void {
        var i: usize = 0;
        while (i < self.thread_list.items.len) {
            if (self.thread_list.items[i] == thread_id) {
                _ = self.thread_list.orderedRemove(i);
                return;
            }
            i += 1;
        }
    }
    
    pub fn iterateThreads(self: Process) []const u32 {
        return self.thread_list.items;
    }
    
    pub fn getContainingModule(self: Process, address: u64) ?*const Module {
        for (self.module_list.items) |*module| {
            if (module.containsAddress(address)) {
                return module;
            }
        }
        return null;
    }
    
    pub fn getContainingModuleMut(self: *Process, address: u64) ?*Module {
        for (self.module_list.items) |*module| {
            if (module.containsAddress(address)) {
                return module;
            }
        }
        return null;
    }
    
    pub fn getModuleByNameMut(self: *Process, module_name: []const u8) ?*Module {
        var potential_trimmed_match: ?*Module = null;
        
        for (self.module_list.items) |*module| {
            // Exact match
            if (std.mem.eql(u8, module.name, module_name)) {
                return module;
            }
            
            // If no exact match yet, try trimmed match (filename only)
            if (potential_trimmed_match == null) {
                // Find the last backslash or forward slash
                var last_sep: ?usize = null;
                for (module.name, 0..) |c, i| {
                    if (c == '\\' or c == '/') {
                        last_sep = i;
                    }
                }
                
                const trimmed = if (last_sep) |sep| module.name[sep + 1..] else module.name;
                
                // Case-insensitive comparison for trimmed match
                if (std.ascii.eqlIgnoreCase(trimmed, module_name)) {
                    potential_trimmed_match = module;
                }
            }
        }
        
        return potential_trimmed_match;
    }
};