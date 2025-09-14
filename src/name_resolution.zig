// TODO: Implement the name_resolution port from dbgrs\src\name_resolution.rs
const Process = @import("./process.zig").Process;

// Resolve symbol name to address
fn resolveNameToAddress(sym: []const u8, process: *Process) !u64 {
    _ = sym;
    _ = process;
    return error.NotImplemented;
}
