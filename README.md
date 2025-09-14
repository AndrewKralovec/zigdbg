# ZigDbg
Windows debugger written in Zig

ZigDbg is a debugger project written in [Zig](https://ziglang.org/) for Windows.  
It follows the blog series [Writing a Debugger From Scratch](https://www.timdbg.com/posts/writing-a-debugger-from-scratch-part-1/) by [Tim Misiak](https://github.com/timmisiak).  
The goal is to follow the tutorial in Zig, experiment, and learn.

While searching for a debugger for zig application, I came across WinDbg and eventually found Tim’s excellent series. The articles were so interesting that I decided to follow along using zig.

## Getting Started

### Prerequisites

- [Zig](https://ziglang.org/) (version 0.14.0 or later)
- [Windows](https://www.microsoft.com/en-us/windows) (64-bit only)

### Building

To build the project, use the following command

```bash
zig build
```

### Testing

To run the project tests

```bash
zig build test
```

## TODO
- [x] [Writing a Debugger From Scratch - DbgRs Part 1 - Attaching to a Process](https://www.timdbg.com/posts/writing-a-debugger-from-scratch-part-1/)
- [x] [Writing a Debugger From Scratch - DbgRs Part 2 - Register State and Stepping](https://www.timdbg.com/posts/writing-a-debugger-from-scratch-part-2/)
- [x] [Writing a Debugger From Scratch - DbgRs Part 3 - Reading Memory](https://www.timdbg.com/posts/writing-a-debugger-from-scratch-part-3/)
- [x] [Writing a Debugger From Scratch - DbgRs Part 4 - Exports and Private Symbols](https://www.timdbg.com/posts/writing-a-debugger-from-scratch-part-4/)
- [x] [Writing a Debugger From Scratch - DbgRs Part 5 - Breakpoints](https://www.timdbg.com/posts/writing-a-debugger-from-scratch-part-5/)
- [ ] [Writing a Debugger From Scratch - DbgRs Part 6 - Stacks](https://www.timdbg.com/posts/writing-a-debugger-from-scratch-part-6/)
- [ ] [Writing a Debugger From Scratch - DbgRs Part 7 - Disassembly](https://www.timdbg.com/posts/writing-a-debugger-from-scratch-part-7/)
- [ ] [Writing a Debugger From Scratch - DbgRs Part 8 - Source and Symbols](https://www.timdbg.com/posts/writing-a-debugger-from-scratch-part-8/)


## Development Notes

### Debugger System Features
- **Debugger Commands**: `t`, `g`, `r`, `bp`, `bc`, `bl`, `k`, `db`, `?`, `ln`, `q`, `help`
- **Expression Parser**: Supports hex (`0x1234`), decimal (`123`), symbols (`module!symbol`), arithmetic (`expr + expr`)
- **Register Display**: Complete x64 register dump with proper formatting
- **Memory Inspection**: Hex dump with ASCII representation (`db 0x401000`)
- **Single-Step Execution**: Step-into debugging with CPU trap flag
- **Breakpoints**: Set, clear, and list breakpoints with address resolution
- **Symbol Resolution**: Load and resolve symbols from PE exports
- **Error Handling**: Comprehensive error reporting and command validation

### Debugger Usage
```bash
zig build run -- hello_world.exe

# Console prompt appears on debug events:
[1234] 0x00007ff6a2b41000
> help                    # Show available commands
> r                       # Display all registers
> db 0x00007ff6a2b41000   # Dump memory at address
> ? 0x1000 + 0x200        # Evaluate arithmetic expression
> t                       # Single step execution
> g                       # Continue execution
> q                       # Quit debugger
```