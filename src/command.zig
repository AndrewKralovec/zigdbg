const std = @import("std");
const Allocator = std.mem.Allocator;
const print = std.debug.print;

const eval = @import("eval.zig");
const process_mod = @import("process.zig");

// Command enumeration with parameters
pub const Command = union(enum) {
    StepInto,
    Go,
    DisplayRegisters,
    DisplayBytes: u64,
    Evaluate: u64,
    ListNearest: u64,
    SetBreakpoint: u64,
    ListBreakpoints,
    ClearBreakpoint: u32,
    CallStack,
    Quit,
    Unknown,
};

// Extended command parsing with expressions and breakpoints
pub fn readCommand(allocator: Allocator, process_info: *process_mod.Process) !Command {
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
                } else if (std.mem.eql(u8, trimmed, "bl")) {
                    return Command.ListBreakpoints;
                } else if (std.mem.eql(u8, trimmed, "k")) {
                    return Command.CallStack;
                } else if (std.mem.startsWith(u8, trimmed, "bp ")) {
                    const expr_text = trimmed[3..];
                    var expr = eval.parseExpression(allocator, expr_text) catch {
                        print("Invalid expression in bp command\n", .{});
                        continue;
                    };
                    defer expr.deinit(allocator);
                    const addr = expr.evaluate(allocator, process_info) catch |err| {
                        print("Failed to evaluate breakpoint address: {any}\n", .{err});
                        continue;
                    };
                    return Command{ .SetBreakpoint = addr };
                } else if (std.mem.startsWith(u8, trimmed, "bc ")) {
                    const expr_text = trimmed[3..];
                    var expr = eval.parseExpression(allocator, expr_text) catch {
                        print("Invalid expression in bc command\n", .{});
                        continue;
                    };
                    defer expr.deinit(allocator);
                    const id = expr.evaluate(allocator, process_info) catch |err| {
                        print("Failed to evaluate breakpoint ID: {any}\n", .{err});
                        continue;
                    };
                    return Command{ .ClearBreakpoint = @intCast(id) };
                } else if (std.mem.startsWith(u8, trimmed, "db ")) {
                    const expr_text = trimmed[3..];
                    var expr = eval.parseExpression(allocator, expr_text) catch {
                        print("Invalid expression in db command\n", .{});
                        continue;
                    };
                    defer expr.deinit(allocator);
                    const addr = expr.evaluate(allocator, process_info) catch |err| {
                        print("Failed to evaluate address: {any}\n", .{err});
                        continue;
                    };
                    return Command{ .DisplayBytes = addr };
                } else if (std.mem.startsWith(u8, trimmed, "ln ")) {
                    const expr_text = trimmed[3..];
                    var expr = eval.parseExpression(allocator, expr_text) catch {
                        print("Invalid expression in ln command\n", .{});
                        continue;
                    };
                    defer expr.deinit(allocator);
                    const addr = expr.evaluate(allocator, process_info) catch |err| {
                        print("Failed to evaluate address: {any}\n", .{err});
                        continue;
                    };
                    return Command{ .ListNearest = addr };
                } else if (std.mem.startsWith(u8, trimmed, "? ")) {
                    const expr_text = trimmed[2..];
                    var expr = eval.parseExpression(allocator, expr_text) catch {
                        print("Invalid expression in ? command\n", .{});
                        continue;
                    };
                    defer expr.deinit(allocator);
                    const value = expr.evaluate(allocator, process_info) catch |err| {
                        print("Failed to evaluate expression: {any}\n", .{err});
                        continue;
                    };
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
                    print("  bp <addr> - set breakpoint at address\n", .{});
                    print("  bl - list breakpoints\n", .{});
                    print("  bc <id> - clear breakpoint by ID\n", .{});
                    print("  k - display call stack\n", .{});
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