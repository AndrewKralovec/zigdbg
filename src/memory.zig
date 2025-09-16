const std = @import("std");
const windows = std.os.windows;
const Allocator = std.mem.Allocator;

extern "kernel32" fn ReadProcessMemory(
    hProcess: windows.HANDLE,
    lpBaseAddress: ?*const anyopaque,
    lpBuffer: [*]u8,
    nSize: usize,
    lpNumberOfBytesRead: ?*usize,
) callconv(windows.WINAPI) windows.BOOL;

// Read memory from process
pub fn readProcessMemoryBytes(process: windows.HANDLE, address: u64, buffer: []u8) !usize {
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
pub fn readProcessMemoryData(comptime T: type, process: windows.HANDLE, address: u64) !T {
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
pub fn readProcessMemoryArray(comptime T: type, allocator: Allocator, process: windows.HANDLE, address: u64, count: u32) ![]T {
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
pub fn readProcessMemoryString(allocator: Allocator, process: windows.HANDLE, address: u64, max_len: usize, is_wide: bool) ![]u8 {
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