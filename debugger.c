#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define MAX_BREAKPOINTS 64
#define INT3_OPCODE 0xCC

typedef struct {
    unsigned long addr;
    unsigned char original_byte;
    int active;
} breakpoint_t;

typedef struct {
    pid_t pid;
    char *binary_path;
    Elf64_Ehdr *elf_header;
    Elf64_Phdr *program_headers;
    Elf64_Shdr *section_headers;
    char *section_strings;
    unsigned long base_addr;
    breakpoint_t breakpoints[MAX_BREAKPOINTS];
    int num_breakpoints;
} debugger_t;

debugger_t *init_debugger(char *binary_path) {
    debugger_t *dbg = calloc(1, sizeof(debugger_t));
    dbg->binary_path = strdup(binary_path);
    dbg->pid = -1;
    dbg->num_breakpoints = 0;
    return dbg;
}

int parse_elf_header(debugger_t *dbg) {
    int fd = open(dbg->binary_path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return -1;
    }

    void *mapped = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapped == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return -1;
    }

    dbg->elf_header = (Elf64_Ehdr *)mapped;
    
    if (memcmp(dbg->elf_header->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not a valid ELF file\n");
        munmap(mapped, st.st_size);
        close(fd);
        return -1;
    }

    dbg->program_headers = (Elf64_Phdr *)((char *)mapped + dbg->elf_header->e_phoff);
    dbg->section_headers = (Elf64_Shdr *)((char *)mapped + dbg->elf_header->e_shoff);
    
    if (dbg->elf_header->e_shstrndx != SHN_UNDEF) {
        dbg->section_strings = (char *)mapped + dbg->section_headers[dbg->elf_header->e_shstrndx].sh_offset;
    }

    close(fd);
    return 0;
}

unsigned long get_base_address(debugger_t *dbg) {
    char maps_path[32];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", dbg->pid);
    
    FILE *maps = fopen(maps_path, "r");
    if (!maps) {
        perror("fopen maps");
        return 0;
    }

    char line[256];
    unsigned long addr = 0;
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, dbg->binary_path)) {
            sscanf(line, "%lx", &addr);
            break;
        }
    }
    
    fclose(maps);
    return addr;
}

int start_process(debugger_t *dbg, char *argv[]) {
    pid_t pid = fork();
    
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace TRACEME");
            exit(1);
        }
        execv(dbg->binary_path, argv);
        perror("execv");
        exit(1);
    } else if (pid > 0) {
        dbg->pid = pid;
        int status;
        waitpid(pid, &status, 0);
        
        if (WIFSTOPPED(status)) {
            dbg->base_addr = get_base_address(dbg);
            return 0;
        }
    }
    
    return -1;
}

int set_breakpoint(debugger_t *dbg, unsigned long addr) {
    if (dbg->num_breakpoints >= MAX_BREAKPOINTS) {
        fprintf(stderr, "Maximum breakpoints reached\n");
        return -1;
    }

    unsigned long data = ptrace(PTRACE_PEEKTEXT, dbg->pid, addr, NULL);
    if (errno != 0) {
        perror("ptrace PEEKTEXT");
        return -1;
    }

    breakpoint_t *bp = &dbg->breakpoints[dbg->num_breakpoints];
    bp->addr = addr;
    bp->original_byte = data & 0xFF;
    bp->active = 1;

    unsigned long patched_data = (data & ~0xFF) | INT3_OPCODE;
    if (ptrace(PTRACE_POKETEXT, dbg->pid, addr, patched_data) < 0) {
        perror("ptrace POKETEXT");
        return -1;
    }

    dbg->num_breakpoints++;
    printf("Breakpoint set at 0x%lx\n", addr);
    return 0;
}

int remove_breakpoint(debugger_t *dbg, unsigned long addr) {
    for (int i = 0; i < dbg->num_breakpoints; i++) {
        breakpoint_t *bp = &dbg->breakpoints[i];
        if (bp->addr == addr && bp->active) {
            unsigned long data = ptrace(PTRACE_PEEKTEXT, dbg->pid, addr, NULL);
            unsigned long restored_data = (data & ~0xFF) | bp->original_byte;
            
            if (ptrace(PTRACE_POKETEXT, dbg->pid, addr, restored_data) < 0) {
                perror("ptrace POKETEXT");
                return -1;
            }
            
            bp->active = 0;
            printf("Breakpoint removed from 0x%lx\n", addr);
            return 0;
        }
    }
    
    fprintf(stderr, "No active breakpoint at 0x%lx\n", addr);
    return -1;
}

breakpoint_t *find_breakpoint(debugger_t *dbg, unsigned long addr) {
    for (int i = 0; i < dbg->num_breakpoints; i++) {
        if (dbg->breakpoints[i].addr == addr && dbg->breakpoints[i].active) {
            return &dbg->breakpoints[i];
        }
    }
    return NULL;
}

int handle_breakpoint(debugger_t *dbg, unsigned long addr) {
    breakpoint_t *bp = find_breakpoint(dbg, addr);
    if (!bp) {
        return -1;
    }

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, dbg->pid, NULL, &regs) < 0) {
        perror("ptrace GETREGS");
        return -1;
    }

    regs.rip = addr;
    if (ptrace(PTRACE_SETREGS, dbg->pid, NULL, &regs) < 0) {
        perror("ptrace SETREGS");
        return -1;
    }

    unsigned long data = ptrace(PTRACE_PEEKTEXT, dbg->pid, addr, NULL);
    unsigned long restored_data = (data & ~0xFF) | bp->original_byte;
    if (ptrace(PTRACE_POKETEXT, dbg->pid, addr, restored_data) < 0) {
        perror("ptrace POKETEXT");
        return -1;
    }

    if (ptrace(PTRACE_SINGLESTEP, dbg->pid, NULL, NULL) < 0) {
        perror("ptrace SINGLESTEP");
        return -1;
    }

    int status;
    waitpid(dbg->pid, &status, 0);

    unsigned long patched_data = (restored_data & ~0xFF) | INT3_OPCODE;
    if (ptrace(PTRACE_POKETEXT, dbg->pid, addr, patched_data) < 0) {
        perror("ptrace POKETEXT");
        return -1;
    }

    return 0;
}

void print_registers(debugger_t *dbg) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, dbg->pid, NULL, &regs) < 0) {
        perror("ptrace GETREGS");
        return;
    }

    printf("RAX: 0x%llx  RBX: 0x%llx  RCX: 0x%llx  RDX: 0x%llx\n", 
           regs.rax, regs.rbx, regs.rcx, regs.rdx);
    printf("RSI: 0x%llx  RDI: 0x%llx  RBP: 0x%llx  RSP: 0x%llx\n", 
           regs.rsi, regs.rdi, regs.rbp, regs.rsp);
    printf("RIP: 0x%llx  RFLAGS: 0x%llx\n", regs.rip, regs.eflags);
}

void print_elf_info(debugger_t *dbg) {
    printf("ELF Header:\n");
    printf("  Entry point: 0x%lx\n", dbg->elf_header->e_entry);
    printf("  Program headers: %d\n", dbg->elf_header->e_phnum);
    printf("  Section headers: %d\n", dbg->elf_header->e_shnum);
    printf("  Base address: 0x%lx\n", dbg->base_addr);
    
    printf("\nProgram Headers:\n");
    for (int i = 0; i < dbg->elf_header->e_phnum; i++) {
        Elf64_Phdr *ph = &dbg->program_headers[i];
        if (ph->p_type == PT_LOAD) {
            printf("  LOAD: 0x%lx - 0x%lx (file: 0x%lx)\n", 
                   ph->p_vaddr, ph->p_vaddr + ph->p_memsz, ph->p_offset);
        }
    }
}

void debug_loop(debugger_t *dbg) {
    char input[256];
    
    printf("Tiny Debugger - Type 'help' for commands\n");
    
    while (1) {
        printf("(tdb) ");
        fflush(stdout);
        
        if (!fgets(input, sizeof(input), stdin)) {
            break;
        }
        
        char *cmd = strtok(input, " \t\n");
        if (!cmd) continue;
        
        if (strcmp(cmd, "help") == 0) {
            printf("Commands:\n");
            printf("  break <addr>  - Set breakpoint at address\n");
            printf("  delete <addr> - Remove breakpoint\n");
            printf("  continue      - Continue execution\n");
            printf("  step          - Single step\n");
            printf("  registers     - Show registers\n");
            printf("  info          - Show ELF info\n");
            printf("  quit          - Exit debugger\n");
        }
        else if (strcmp(cmd, "break") == 0) {
            char *addr_str = strtok(NULL, " \t\n");
            if (addr_str) {
                unsigned long addr = strtoul(addr_str, NULL, 0);
                set_breakpoint(dbg, addr);
            }
        }
        else if (strcmp(cmd, "delete") == 0) {
            char *addr_str = strtok(NULL, " \t\n");
            if (addr_str) {
                unsigned long addr = strtoul(addr_str, NULL, 0);
                remove_breakpoint(dbg, addr);
            }
        }
        else if (strcmp(cmd, "continue") == 0) {
            if (ptrace(PTRACE_CONT, dbg->pid, NULL, NULL) < 0) {
                perror("ptrace CONT");
                continue;
            }
            
            int status;
            waitpid(dbg->pid, &status, 0);
            
            if (WIFEXITED(status)) {
                printf("Process exited with status %d\n", WEXITSTATUS(status));
                break;
            }
            
            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, dbg->pid, NULL, &regs);
                unsigned long addr = regs.rip - 1;
                
                if (find_breakpoint(dbg, addr)) {
                    printf("Breakpoint hit at 0x%lx\n", addr);
                    handle_breakpoint(dbg, addr);
                }
            }
        }
        else if (strcmp(cmd, "step") == 0) {
            if (ptrace(PTRACE_SINGLESTEP, dbg->pid, NULL, NULL) < 0) {
                perror("ptrace SINGLESTEP");
                continue;
            }
            
            int status;
            waitpid(dbg->pid, &status, 0);
            
            if (WIFEXITED(status)) {
                printf("Process exited with status %d\n", WEXITSTATUS(status));
                break;
            }
        }
        else if (strcmp(cmd, "registers") == 0) {
            print_registers(dbg);
        }
        else if (strcmp(cmd, "info") == 0) {
            print_elf_info(dbg);
        }
        else if (strcmp(cmd, "quit") == 0) {
            break;
        }
        else {
            printf("Unknown command: %s\n", cmd);
        }
    }
}

void cleanup_debugger(debugger_t *dbg) {
    if (dbg->pid > 0) {
        ptrace(PTRACE_DETACH, dbg->pid, NULL, NULL);
    }
    
    if (dbg->binary_path) {
        free(dbg->binary_path);
    }
    
    free(dbg);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <binary> [args...]\n", argv[0]);
        return 1;
    }

    debugger_t *dbg = init_debugger(argv[1]);
    
    if (parse_elf_header(dbg) < 0) {
        fprintf(stderr, "Failed to parse ELF header\n");
        cleanup_debugger(dbg);
        return 1;
    }

    if (start_process(dbg, &argv[1]) < 0) {
        fprintf(stderr, "Failed to start process\n");
        cleanup_debugger(dbg);
        return 1;
    }

    debug_loop(dbg);
    cleanup_debugger(dbg);
    return 0;
}
