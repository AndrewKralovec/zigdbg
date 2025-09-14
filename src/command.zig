const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;
const eval = @import("eval.zig");
const EvalExpr = eval.EvalExpr;

// Command types supported by the debugger
pub const CommandExpr = union(enum) {
    StepInto,
    Go,
    SetBreakpoint: EvalExpr,
    ListBreakpoints,
    ClearBreakpoint: EvalExpr,
    DisplayRegisters,
    StackWalk,
    DisplayBytes: EvalExpr,
    Evaluate: EvalExpr,
    ListNearest: EvalExpr,
    Quit,
    Help,
    Invalid: []u8,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: Allocator) void {
        switch (self.*) {
            .SetBreakpoint => |*expr| expr.deinit(allocator),
            .ClearBreakpoint => |*expr| expr.deinit(allocator),
            .DisplayBytes => |*expr| expr.deinit(allocator),
            .Evaluate => |*expr| expr.deinit(allocator),
            .ListNearest => |*expr| expr.deinit(allocator),
            .Invalid => |msg| allocator.free(msg),
            else => {},
        }
    }
};

// Simple command parser
fn parseCommand(allocator: Allocator, input: []const u8) !CommandExpr {
    const trimmed = std.mem.trim(u8, input, " \t\r\n");
    if (trimmed.len == 0) {
        return CommandExpr{ .Invalid = try allocator.dupe(u8, "Empty command") };
    }

    // Split command and arguments
    var parts = std.mem.splitScalar(u8, trimmed, ' ');
    const command = parts.next() orelse return CommandExpr{ .Invalid = try allocator.dupe(u8, "No command") };

    // Parse single-character commands
    if (std.mem.eql(u8, command, "t")) {
        return CommandExpr.StepInto;
    } else if (std.mem.eql(u8, command, "g")) {
        return CommandExpr.Go;
    } else if (std.mem.eql(u8, command, "r")) {
        return CommandExpr.DisplayRegisters;
    } else if (std.mem.eql(u8, command, "k")) {
        return CommandExpr.StackWalk;
    } else if (std.mem.eql(u8, command, "q")) {
        return CommandExpr.Quit;
    } else if (std.mem.eql(u8, command, "bl")) {
        return CommandExpr.ListBreakpoints;
    } else if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "h")) {
        return CommandExpr.Help;
    }

    // Parse commands with arguments
    const rest_of_line = parts.rest();
    if (rest_of_line.len == 0) {
        const error_msg = try std.fmt.allocPrint(allocator, "Command '{s}' requires an argument", .{command});
        return CommandExpr{ .Invalid = error_msg };
    }

    if (std.mem.eql(u8, command, "bp")) {
        const expr = eval.parseExpression(allocator, rest_of_line) catch |err| {
            const error_msg = try std.fmt.allocPrint(allocator, "Failed to parse breakpoint expression: {any}", .{err});
            return CommandExpr{ .Invalid = error_msg };
        };
        return CommandExpr{ .SetBreakpoint = expr };
    } else if (std.mem.eql(u8, command, "bc")) {
        const expr = eval.parseExpression(allocator, rest_of_line) catch |err| {
            const error_msg = try std.fmt.allocPrint(allocator, "Failed to parse clear breakpoint expression: {any}", .{err});
            return CommandExpr{ .Invalid = error_msg };
        };
        return CommandExpr{ .ClearBreakpoint = expr };
    } else if (std.mem.eql(u8, command, "db")) {
        const expr = eval.parseExpression(allocator, rest_of_line) catch |err| {
            const error_msg = try std.fmt.allocPrint(allocator, "Failed to parse memory display expression: {any}", .{err});
            return CommandExpr{ .Invalid = error_msg };
        };
        return CommandExpr{ .DisplayBytes = expr };
    } else if (std.mem.eql(u8, command, "?")) {
        const expr = eval.parseExpression(allocator, rest_of_line) catch |err| {
            const error_msg = try std.fmt.allocPrint(allocator, "Failed to parse evaluate expression: {any}", .{err});
            return CommandExpr{ .Invalid = error_msg };
        };
        return CommandExpr{ .Evaluate = expr };
    } else if (std.mem.eql(u8, command, "ln")) {
        const expr = eval.parseExpression(allocator, rest_of_line) catch |err| {
            const error_msg = try std.fmt.allocPrint(allocator, "Failed to parse list nearest expression: {any}", .{err});
            return CommandExpr{ .Invalid = error_msg };
        };
        return CommandExpr{ .ListNearest = expr };
    }

    const error_msg = try std.fmt.allocPrint(allocator, "Unknown command: '{s}'", .{command});
    return CommandExpr{ .Invalid = error_msg };
}

// Read and parse a command from user input
pub fn readCommand(allocator: Allocator) !CommandExpr {
    const stdin = std.io.getStdIn().reader();

    while (true) {
        // Print prompt
        try std.io.getStdOut().writer().print("> ", .{});

        // Read line
        var input_buffer: [1024]u8 = undefined;
        if (try stdin.readUntilDelimiterOrEof(input_buffer[0..], '\n')) |input| {
            const command = parseCommand(allocator, input) catch |err| {
                print("Error parsing command: {any}\n", .{err});
                continue;
            };

            // Check if it's an invalid command and display the error
            switch (command) {
                .Invalid => |msg| {
                    print("Error: {s}\n", .{msg});
                    var cmd_copy = command;
                    cmd_copy.deinit(allocator);
                    continue;
                },
                else => return command,
            }
        }
    }
}

// Display help information
pub fn displayHelp() void {
    print("Available commands:\\n", .{});
    print("  t            - Step into (single step)\\n", .{});
    print("  g            - Go (continue execution)\\n", .{});
    print("  bp <expr>    - Set breakpoint at address/symbol\\n", .{});
    print("  bl           - List breakpoints\\n", .{});
    print("  bc <expr>    - Clear breakpoint\\n", .{});
    print("  r            - Display registers\\n", .{});
    print("  k            - Stack walk\\n", .{});
    print("  db <expr>    - Display bytes at address\\n", .{});
    print("  ? <expr>     - Evaluate expression\\n", .{});
    print("  ln <expr>    - List nearest symbols\\n", .{});
    print("  q            - Quit\\n", .{});
    print("  help         - Show this help\\n", .{});
    print("\\n", .{});
    print("Expressions can be:\\n", .{});
    print("  - Numbers: 123, 0x1234\\n", .{});
    print("  - Symbols: module!symbol\\n", .{});
    print("  - Arithmetic: expr + expr\\n", .{});
}
