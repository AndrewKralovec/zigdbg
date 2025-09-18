const std = @import("std");
const windows = std.os.windows;
const com_interfaces = @import("com_interfaces.zig");

// Import types from com_interfaces
const HRESULT = com_interfaces.HRESULT;
const GUID = com_interfaces.GUID;
const ULONG = com_interfaces.ULONG;
const IUnknown = com_interfaces.IUnknown;
const IDebugClient5 = com_interfaces.IDebugClient5;
const IDebugControl4 = com_interfaces.IDebugControl4;

// COM error codes
pub const S_OK: HRESULT = 0;
pub const S_FALSE: HRESULT = 1;
pub const E_FAIL: HRESULT = @bitCast(@as(u32, 0x80004005));
pub const E_INVALIDARG: HRESULT = @bitCast(@as(u32, 0x80070057));
pub const E_NOINTERFACE: HRESULT = @bitCast(@as(u32, 0x80004002));
pub const E_OUTOFMEMORY: HRESULT = @bitCast(@as(u32, 0x8007000E));
pub const E_NOTIMPL: HRESULT = @bitCast(@as(u32, 0x80004001));

// COM threading model
pub const COINIT_APARTMENTTHREADED: windows.DWORD = 0x2;
pub const COINIT_MULTITHREADED: windows.DWORD = 0x0;
pub const COINIT_DISABLE_OLE1DDE: windows.DWORD = 0x4;
pub const COINIT_SPEED_OVER_MEMORY: windows.DWORD = 0x8;

// External COM functions
extern "ole32" fn CoInitializeEx(
    pvReserved: ?*anyopaque,
    dwCoInit: windows.DWORD,
) callconv(windows.WINAPI) HRESULT;

extern "ole32" fn CoUninitialize() callconv(windows.WINAPI) void;

extern "ole32" fn CoCreateInstance(
    rclsid: *const GUID,
    pUnkOuter: ?*IUnknown,
    dwClsContext: windows.DWORD,
    riid: *const GUID,
    ppv: *?*anyopaque,
) callconv(windows.WINAPI) HRESULT;

// COM class context
pub const CLSCTX_INPROC_SERVER: windows.DWORD = 0x1;
pub const CLSCTX_INPROC_HANDLER: windows.DWORD = 0x2;
pub const CLSCTX_LOCAL_SERVER: windows.DWORD = 0x4;
pub const CLSCTX_REMOTE_SERVER: windows.DWORD = 0x10;
pub const CLSCTX_ALL: windows.DWORD = CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER | CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER;

/// COM initialization wrapper with RAII cleanup
pub const ComInitializer = struct {
    initialized: bool,

    const Self = @This();

    /// Initialize COM with the specified threading model
    pub fn init(threading_model: windows.DWORD) !Self {
        const flags = threading_model | COINIT_DISABLE_OLE1DDE;
        const hr = CoInitializeEx(null, flags);

        // S_FALSE means COM was already initialized, which is acceptable
        if (hr != S_OK and hr != S_FALSE) {
            return error.ComInitializationFailed;
        }

        return Self{
            .initialized = true,
        };
    }

    /// Initialize COM with apartment threading (recommended for most cases)
    pub fn initApartmentThreaded() !Self {
        return init(COINIT_APARTMENTTHREADED);
    }

    /// Initialize COM with multithreaded model
    pub fn initMultiThreaded() !Self {
        return init(COINIT_MULTITHREADED);
    }

    /// Clean up COM initialization
    pub fn deinit(self: *Self) void {
        if (self.initialized) {
            CoUninitialize();
            self.initialized = false;
        }
    }
};

/// Generic COM interface wrapper with automatic reference counting
pub fn ComInterface(comptime T: type) type {
    return struct {
        interface: ?*T,

        const Self = @This();

        /// Create a COM interface wrapper from an existing interface pointer
        pub fn from(interface: *T) Self {
            // AddRef the interface to maintain proper reference counting
            _ = interface.addRef();
            return Self{
                .interface = interface,
            };
        }

        /// Create a COM interface wrapper without adding a reference
        /// Use this when you're taking ownership of an already-addref'd interface
        pub fn fromOwned(interface: *T) Self {
            return Self{
                .interface = interface,
            };
        }

        /// Get the underlying interface pointer (nullable)
        pub fn get(self: *const Self) ?*T {
            return self.interface;
        }

        /// Get the underlying interface pointer (non-null, panics if null)
        pub fn getRequired(self: *const Self) *T {
            return self.interface orelse @panic("COM interface is null");
        }

        /// Check if the interface is valid (not null)
        pub fn isValid(self: *const Self) bool {
            return self.interface != null;
        }

        /// Query for another interface from this one
        pub fn queryInterface(self: *const Self, comptime U: type, riid: *const GUID) !ComInterface(U) {
            const interface = self.getRequired();
            var result: ?*anyopaque = null;
            const hr = interface.queryInterface(riid, &result);

            if (hr != S_OK) {
                return error.QueryInterfaceFailed;
            }

            const typed_interface = @as(*U, @ptrCast(@alignCast(result.?)));
            return ComInterface(U).fromOwned(typed_interface);
        }

        /// Release the interface and set to null
        pub fn deinit(self: *Self) void {
            if (self.interface) |interface| {
                _ = interface.release();
                self.interface = null;
            }
        }
    };
}

/// Type aliases for common COM interface wrappers
pub const ComClient = ComInterface(IDebugClient5);
pub const ComControl = ComInterface(IDebugControl4);

/// Convenience function to check if HRESULT indicates success
pub fn succeeded(hr: HRESULT) bool {
    return hr >= 0;
}

/// Convenience function to check if HRESULT indicates failure
pub fn failed(hr: HRESULT) bool {
    return hr < 0;
}

/// Convert HRESULT to a descriptive error
pub fn hresultToError(hr: HRESULT) error{
    ComInitializationFailed,
    QueryInterfaceFailed,
    InvalidArgument,
    OutOfMemory,
    NotImplemented,
    NoInterface,
    GeneralFailure,
    UnknownError,
} {
    return switch (hr) {
        S_OK, S_FALSE => error.UnknownError, // Should not be called for success codes
        E_INVALIDARG => error.InvalidArgument,
        E_OUTOFMEMORY => error.OutOfMemory,
        E_NOTIMPL => error.NotImplemented,
        E_NOINTERFACE => error.NoInterface,
        E_FAIL => error.GeneralFailure,
        else => error.UnknownError,
    };
}

/// Error handling wrapper for HRESULT-returning functions
pub fn hresultWrap(hr: HRESULT) !void {
    if (failed(hr)) {
        return hresultToError(hr);
    }
}

/// Create a wide string from a UTF-8 string for COM APIs
pub fn createWideString(allocator: std.mem.Allocator, utf8_string: []const u8) ![:0]u16 {
    return std.unicode.utf8ToUtf16LeAllocZ(allocator, utf8_string);
}

/// Convert a wide string back to UTF-8
pub fn wideStringToUtf8(allocator: std.mem.Allocator, wide_string: [*:0]const u16) ![]u8 {
    const wide_slice = std.mem.span(wide_string);
    return std.unicode.utf16leToUtf8Alloc(allocator, wide_slice) catch |err| switch (err) {
        error.InvalidUtf16 => return error.InvalidWideString,
        else => return err,
    };
}

/// Safe wrapper for wide string operations
pub const WideString = struct {
    data: [:0]u16,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, utf8_string: []const u8) !Self {
        const wide_data = try createWideString(allocator, utf8_string);
        return Self{
            .data = wide_data,
            .allocator = allocator,
        };
    }

    pub fn ptr(self: *const Self) [*:0]const u16 {
        return self.data.ptr;
    }

    pub fn len(self: *const Self) usize {
        return self.data.len;
    }

    pub fn toUtf8(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        return wideStringToUtf8(allocator, self.data.ptr);
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.data);
    }
};

/// Error set for COM operations
pub const ComError = error{
    ComInitializationFailed,
    QueryInterfaceFailed,
    InvalidArgument,
    OutOfMemory,
    NotImplemented,
    NoInterface,
    GeneralFailure,
    UnknownError,
    InvalidWideString,
};

/// Print HRESULT in a human-readable format
pub fn formatHresult(hr: HRESULT, writer: anytype) !void {
    try writer.print("HRESULT: 0x{X:0>8} (", .{@as(u32, @bitCast(hr))});

    if (succeeded(hr)) {
        try writer.print("SUCCESS", .{});
    } else {
        try writer.print("FAILED", .{});
    }

    switch (hr) {
        S_OK => try writer.print(" - S_OK", .{}),
        S_FALSE => try writer.print(" - S_FALSE", .{}),
        E_FAIL => try writer.print(" - E_FAIL", .{}),
        E_INVALIDARG => try writer.print(" - E_INVALIDARG", .{}),
        E_NOINTERFACE => try writer.print(" - E_NOINTERFACE", .{}),
        E_OUTOFMEMORY => try writer.print(" - E_OUTOFMEMORY", .{}),
        E_NOTIMPL => try writer.print(" - E_NOTIMPL", .{}),
        else => try writer.print(" - UNKNOWN", .{}),
    }

    try writer.print(")", .{});
}

/// Debug helper to print HRESULT information
pub fn debugPrintHresult(hr: HRESULT, context: []const u8) void {
    std.debug.print("{s}: ", .{context});
    formatHresult(hr, std.io.getStdErr().writer()) catch {};
    std.debug.print("\n", .{});
}

test "COM initialization" {
    var com_init = try ComInitializer.initApartmentThreaded();
    defer com_init.deinit();

    // COM should be initialized successfully
    try std.testing.expect(com_init.initialized);
}

test "HRESULT utilities" {
    try std.testing.expect(succeeded(S_OK));
    try std.testing.expect(succeeded(S_FALSE));
    try std.testing.expect(failed(E_FAIL));
    try std.testing.expect(failed(E_INVALIDARG));
}

test "Wide string conversion" {
    const allocator = std.testing.allocator;

    const wide = try createWideString(allocator, "Hello, World!");
    defer allocator.free(wide);

    const utf8_back = try wideStringToUtf8(allocator, wide.ptr);
    defer allocator.free(utf8_back);

    try std.testing.expectEqualStrings("Hello, World!", utf8_back);
}

test "WideString wrapper" {
    const allocator = std.testing.allocator;

    var wide_string = try WideString.init(allocator, "Test String");
    defer wide_string.deinit();

    try std.testing.expect(wide_string.len() > 0);

    const utf8_back = try wide_string.toUtf8(allocator);
    defer allocator.free(utf8_back);

    try std.testing.expectEqualStrings("Test String", utf8_back);
}
