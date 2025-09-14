const std = @import("std");
const Allocator = std.mem.Allocator;
const Process = @import("./process.zig").Process;
const resolveNameToAddress = @import("./name_resolution.zig").resolveNameToAddress;
const print = std.debug.print;

// Expression types for evaluation
const EvalExpr = union(enum) {
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
            .Symbol => |sym| try resolveNameToAddress(sym, process_info),
            .Add => |add| (try add.left.evaluate(allocator, process_info)) + (try add.right.evaluate(allocator, process_info)),
        };
    }
};

// Simple expression parser
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

    // Check if it's a symbol (contains '!' or looks like an identifier)
    if (std.mem.indexOf(u8, trimmed, "!") != null or !std.ascii.isDigit(trimmed[0])) {
        return EvalExpr{ .Symbol = try allocator.dupe(u8, trimmed) };
    }

    // No addition operator found, parse as number
    const num = parseInt(trimmed) catch |err| {
        print("Failed to parse number: {s}\n", .{trimmed});
        return err;
    };

    return EvalExpr{ .Number = num };
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
