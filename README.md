# ZigDbg
Windows debugger written in Zig

ZigDbg is a debugger project written in [Zig](https://ziglang.org/) for Windows.  
It follows the blog series [Writing a Debugger From Scratch](https://www.timdbg.com/posts/writing-a-debugger-from-scratch-part-1/) by [Tim Misiak](https://github.com/timmisiak).

While searching for a Zig-based debugger, I came across WinDbg and eventually found Tim’s excellent series. The articles were so interesting that I decided to follow along using zig. 

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
