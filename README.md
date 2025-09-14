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

### Building and running
To build and run an executable with the debugger, use the following command

```bash
zig build run -- hello_world.exe

# Console prompt appears on debug events:
[1234] 0x00007ff6a2b41000
> help                    # Show available commands
> r                       # Display all registers
> k                       # Show stack trace
> t                       # Single step execution
> g                       # Continue execution
> q                       # Quit debugger
> db 0x00007ff6a2b41000   # Dump memory at address
> bp 0x00007ff8d14ea65    # Set breakpoint
> ? 0x1000 + 0x200        # Evaluate arithmetic expression
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
- [x] [Writing a Debugger From Scratch - DbgRs Part 6 - Stacks](https://www.timdbg.com/posts/writing-a-debugger-from-scratch-part-6/)
- [ ] [Writing a Debugger From Scratch - DbgRs Part 7 - Disassembly](https://www.timdbg.com/posts/writing-a-debugger-from-scratch-part-7/)
- [ ] [Writing a Debugger From Scratch - DbgRs Part 8 - Source and Symbols](https://www.timdbg.com/posts/writing-a-debugger-from-scratch-part-8/)
