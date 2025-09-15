const std = @import("std");
const windows = std.os.windows;
const WINAPI = windows.WINAPI;

// Windows API types
const HANDLE = windows.HANDLE;
const DWORD = windows.DWORD;
const BOOL = windows.BOOL;
const SIZE_T = usize;
const LPVOID = ?*anyopaque;
const LPCVOID = ?*const anyopaque;

// Windows API functions
extern "kernel32" fn ReadProcessMemory(
    hProcess: HANDLE,
    lpBaseAddress: LPCVOID,
    lpBuffer: LPVOID,
    nSize: SIZE_T,
    lpNumberOfBytesRead: ?*SIZE_T,
) callconv(WINAPI) BOOL;

// MemorySource trait equivalent - using interface pattern in Zig
pub const MemorySource = struct {
    const Self = @This();
    
    ptr: *anyopaque,
    vtable: *const VTable,
    
    const VTable = struct {
        readMemory: *const fn(ptr: *anyopaque, address: u64, len: usize, allocator: std.mem.Allocator) anyerror![]?u8,
        readRawMemory: *const fn(ptr: *anyopaque, address: u64, len: usize, allocator: std.mem.Allocator) anyerror![]u8,
        deinit: *const fn(ptr: *anyopaque, allocator: std.mem.Allocator) void,
    };
    
    pub fn init(implementation: anytype, allocator: std.mem.Allocator) !MemorySource {
        const T = @TypeOf(implementation);
        const ptr = try allocator.create(T);
        ptr.* = implementation;
        
        const gen = struct {
            fn readMemory(pointer: *anyopaque, address: u64, len: usize, alloc: std.mem.Allocator) anyerror![]?u8 {
                const self: *T = @ptrCast(@alignCast(pointer));
                return self.readMemory(address, len, alloc);
            }
            
            fn readRawMemory(pointer: *anyopaque, address: u64, len: usize, alloc: std.mem.Allocator) anyerror![]u8 {
                const self: *T = @ptrCast(@alignCast(pointer));
                return self.readRawMemory(address, len, alloc);
            }
            
            fn deinit(pointer: *anyopaque, alloc: std.mem.Allocator) void {
                const self: *T = @ptrCast(@alignCast(pointer));
                if (@hasDecl(T, "deinit")) {
                    self.deinit();
                }
                alloc.destroy(self);
            }
        };
        
        return MemorySource{
            .ptr = ptr,
            .vtable = &.{
                .readMemory = gen.readMemory,
                .readRawMemory = gen.readRawMemory,
                .deinit = gen.deinit,
            },
        };
    }
    
    pub fn deinit(self: MemorySource, allocator: std.mem.Allocator) void {
        self.vtable.deinit(self.ptr, allocator);
    }
    
    // Read up to "len" bytes, return slice of optionals to represent available bytes
    pub fn readMemory(self: MemorySource, address: u64, len: usize, allocator: std.mem.Allocator) ![]?u8 {
        return self.vtable.readMemory(self.ptr, address, len, allocator);
    }
    
    // Read up to "len" bytes, stop at first failure
    pub fn readRawMemory(self: MemorySource, address: u64, len: usize, allocator: std.mem.Allocator) ![]u8 {
        return self.vtable.readRawMemory(self.ptr, address, len, allocator);
    }
};

// Read an array of T from memory
pub fn readMemoryArray(comptime T: type, source: MemorySource, address: u64, max_count: usize, allocator: std.mem.Allocator) ![]T {
    const element_size = @sizeOf(T);
    const max_bytes = max_count * element_size;
    const raw_bytes = try source.readRawMemory(address, max_bytes, allocator);
    defer allocator.free(raw_bytes);
    
    var data = std.ArrayList(T).init(allocator);
    defer data.deinit();
    
    var offset: usize = 0;
    while (offset + element_size <= raw_bytes.len) {
        var item: T = undefined;
        @memcpy(std.mem.asBytes(&item), raw_bytes[offset..offset + element_size]);
        try data.append(item);
        offset += element_size;
    }
    
    return data.toOwnedSlice();
}

// Read exact count of T from memory, fail if can't read all
pub fn readMemoryFullArray(comptime T: type, source: MemorySource, address: u64, count: usize, allocator: std.mem.Allocator) ![]T {
    const arr = try readMemoryArray(T, source, address, count, allocator);
    if (arr.len != count) {
        allocator.free(arr);
        return error.CouldNotReadAllItems;
    }
    return arr;
}

// Read a single value of type T from memory
pub fn readMemoryData(comptime T: type, source: MemorySource, address: u64, allocator: std.mem.Allocator) !T {
    const data = try readMemoryArray(T, source, address, 1, allocator);
    defer allocator.free(data);
    return data[0];
}

// Read a string from memory (null-terminated)
pub fn readMemoryString(source: MemorySource, address: u64, max_count: usize, is_wide: bool, allocator: std.mem.Allocator) ![]u8 {
    if (is_wide) {
        const words = try readMemoryArray(u16, source, address, max_count, allocator);
        defer allocator.free(words);
        
        // Find null terminator
        var null_pos: usize = words.len;
        for (words, 0..) |word, i| {
            if (word == 0) {
                null_pos = i;
                break;
            }
        }
        
        // Convert UTF-16 to UTF-8
        return std.unicode.utf16LeToUtf8Alloc(allocator, words[0..null_pos]);
    } else {
        const bytes = try readMemoryArray(u8, source, address, max_count, allocator);
        
        // Find null terminator
        var null_pos: usize = bytes.len;
        for (bytes, 0..) |byte, i| {
            if (byte == 0) {
                null_pos = i;
                break;
            }
        }
        
        // Create a copy of the string (without null terminator)
        const result = try allocator.alloc(u8, null_pos);
        @memcpy(result, bytes[0..null_pos]);
        allocator.free(bytes);
        return result;
    }
}

// Read a string indirectly (address points to a pointer to the string)
pub fn readMemoryStringIndirect(source: MemorySource, address: u64, max_count: usize, is_wide: bool, allocator: std.mem.Allocator) ![]u8 {
    const string_address = try readMemoryData(u64, source, address, allocator);
    return readMemoryString(source, string_address, max_count, is_wide, allocator);
}

// Live memory source - reads from a running process
const LiveMemorySource = struct {
    hprocess: HANDLE,
    
    pub fn readMemory(self: *LiveMemorySource, address: u64, len: usize, allocator: std.mem.Allocator) ![]?u8 {
        var data = try allocator.alloc(?u8, len);
        @memset(data, null);
        
        const buffer = try allocator.alloc(u8, len);
        defer allocator.free(buffer);
        
        var offset: usize = 0;
        while (offset < len) {
            var bytes_read: SIZE_T = 0;
            const len_left = len - offset;
            const cur_address = address + offset;
            
            const result = ReadProcessMemory(
                self.hprocess,
                @ptrFromInt(cur_address),
                buffer.ptr,
                len_left,
                &bytes_read,
            );
            
            if (result == 0) {
                // Failed to read, but we might have read some bytes successfully before this point
                break;
            }
            
            // Copy successfully read bytes to our result
            for (0..bytes_read) |i| {
                const data_index = offset + i;
                if (data_index < data.len) {
                    data[data_index] = buffer[i];
                }
            }
            
            if (bytes_read > 0) {
                offset += bytes_read;
            } else {
                offset += 1; // Skip to next byte if we can't read at current position
            }
        }
        
        return data;
    }
    
    pub fn readRawMemory(self: *LiveMemorySource, address: u64, len: usize, allocator: std.mem.Allocator) ![]u8 {
        const buffer = try allocator.alloc(u8, len);
        var bytes_read: SIZE_T = 0;
        
        const result = ReadProcessMemory(
            self.hprocess,
            @ptrFromInt(address),
            buffer.ptr,
            len,
            &bytes_read,
        );
        
        if (result == 0 or bytes_read == 0) {
            allocator.free(buffer);
            return allocator.alloc(u8, 0); // Return empty slice on failure
        }
        
        // Resize buffer to actual bytes read
        const actual_data = try allocator.realloc(buffer, bytes_read);
        return actual_data;
    }
};

// Create a live memory source for a process handle
pub fn makeLiveMemorySource(hprocess: HANDLE, allocator: std.mem.Allocator) !MemorySource {
    const live_source = LiveMemorySource{ .hprocess = hprocess };
    return MemorySource.init(live_source, allocator);
}