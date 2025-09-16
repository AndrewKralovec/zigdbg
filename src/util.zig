const std = @import("std");
const windows = std.os.windows;
const Allocator = std.mem.Allocator;

// Helper function to calculate length of null-terminated wide string
pub fn wcslen(ptr: [*:0]const u16) usize {
    var len: usize = 0;
    while (ptr[len] != 0) {
        len += 1;
    }
    return len;
}

// Extracts the filename from a full path string.
// If a backslash is found, returns the substring after the last backslash.
// Otherwise, returns the original string (assumed to be just the filename).
pub fn extractFilename(path: []const u8) []const u8 {
    if (std.mem.lastIndexOf(u8, path, "\\")) |idx| {
        return path[idx + 1 ..];
    }
    return path;
}

// Bit manipulation helper functions
pub fn setBits(val: anytype, set_val: @TypeOf(val.*), start_bit: usize, bit_count: usize) void {
    const T = @TypeOf(val.*);
    const mask: T = (@as(T, 1) << @intCast(bit_count)) - 1;
    const shifted_mask = mask << @intCast(start_bit);
    val.* = (val.* & ~shifted_mask) | ((set_val & mask) << @intCast(start_bit));
}

pub fn getBit(val: u64, bit_pos: usize) bool {
    return (val & (@as(u64, 1) << @intCast(bit_pos))) != 0;
}

// Parse integer from string (hex or decimal)
pub fn parseInt(text: []const u8) !u64 {
    const trimmed = std.mem.trim(u8, text, " \t");
    if (std.mem.startsWith(u8, trimmed, "0x") or std.mem.startsWith(u8, trimmed, "0X")) {
        const hex_part = trimmed[2..];
        return try std.fmt.parseInt(u64, hex_part, 16);
    } else {
        return try std.fmt.parseInt(u64, trimmed, 10);
    }
}

extern "kernel32" fn GetCommandLineW() callconv(windows.WINAPI) [*:0]u16;

pub fn showUsage(error_message: []const u8) void {
    std.debug.print("Error: {s}\n", .{error_message});
    std.debug.print("Usage: zig-debugger <Command Line>\n", .{});
}

// Parse command line to extract the target process command line
pub fn parseCommandLine(allocator: Allocator) ![]u16 {
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
