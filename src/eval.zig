const std = @import("std");
const Allocator = std.mem.Allocator;
const print = std.debug.print;

const util = @import("util.zig");
const name_resolution = @import("name_resolution.zig");
const Process = @import("process.zig").Process;

// Expression types for evaluation
pub const EvalExpr = union(enum) {
    Number: u64,
    Symbol: []u8,
    Add: struct {
        left: *EvalExpr,
        right: *EvalExpr,
    },

    const Self = @This();

    pub fn deinit(self: *Self, allocator: Allocator) void {
        switch (self.*) {
            .Number => {},
            .Symbol => |sym| allocator.free(sym),
            .Add => |add| {
                add.left.deinit(allocator);
                add.right.deinit(allocator);
                allocator.destroy(add.left);
                allocator.destroy(add.right);
            },
        }
    }

    pub fn evaluate(self: *const Self, allocator: Allocator, process_info: *Process) !u64 {
        return switch (self.*) {
            .Number => |n| n,
            .Symbol => |sym| try name_resolution.resolveNameToAddress(sym, process_info),
            .Add => |add| (try add.left.evaluate(allocator, process_info)) + (try add.right.evaluate(allocator, process_info)),
        };
    }
};

// Simple expression parser
pub fn parseExpression(allocator: Allocator, text: []const u8) !EvalExpr {
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

    // Check if it's a symbol (contains '!' or looks like an identifier)
    if (std.mem.indexOf(u8, trimmed, "!") != null or !std.ascii.isDigit(trimmed[0])) {
        return EvalExpr{ .Symbol = try allocator.dupe(u8, trimmed) };
    }

    // No addition operator found, parse as number
    const num = util.parseInt(trimmed) catch |err| {
        print("Failed to parse number: {s}\n", .{trimmed});
        return err;
    };

    return EvalExpr{ .Number = num };
}
