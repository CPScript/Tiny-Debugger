### This is a tiny debugger that reads ELF headers and implements software breakpoints using ptrace. The debugger provides:

**Core Capabilities:**
- ELF64 header parsing with program/section header analysis
- Process spawning and attachment via ptrace
- Software breakpoint implementation using INT3 (0xCC) opcode patching
- Breakpoint management with original instruction preservation
- Interactive debugging interface with essential commands

**Technical Implementation:**
- Uses mmap for efficient ELF file parsing and validation
- Employs ptrace system calls (TRACEME, PEEKTEXT, POKETEXT, GETREGS, SETREGS, SINGLESTEP, CONT) for process control
- Determines runtime base addresses via /proc/pid/maps parsing
- Implements proper breakpoint handling with instruction pointer restoration and single-step execution
- Maintains breakpoint state with original byte preservation for accurate restoration

**Debugging Features:**
- Set/remove breakpoints at arbitrary addresses
- Continue execution until breakpoint or process termination
- Single-step instruction execution
- Register state inspection (RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, RIP, RFLAGS)
- ELF binary information display including entry points and memory segments

The debugger handles process lifecycle management, memory protection, and proper cleanup. It's suitable for analyzing x86-64 ELF binaries and supports typical debugging workflows required for malware analysis and exploitation research.
