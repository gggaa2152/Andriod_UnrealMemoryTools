// ============================================================================
//  UnrealMemoryTools 配套注入器 (arm64 / Android)
// ----------------------------------------------------------------------------
//  采用经典 ptrace + 远程 dlopen 方案：
//    1. ptrace(ATTACH) 挂上目标游戏进程
//    2. 解析 linker64 导出表定位 dlopen 地址
//    3. 在目标进程栈上写入 .so 路径，设置 x0/x1/pc/lr 后 CONT
//    4. lr 指向一段 brk #0 陷阱，dlopen 返回后触发 SIGTRAP，读回 x0 = handle
//    5. 恢复寄存器并 DETACH
//
//  用法:
//    injector -n <包名> -l /data/local/tmp/libUnrealMemoryTools.so
//    injector -p <pid>   -l /data/local/tmp/libUnrealMemoryTools.so
//
//  需要 root（ptrace attach 非子进程）。
// ============================================================================

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/procfs.h>
#include <elf.h>

// aarch64 的 bionic <sys/ptrace.h> 未定义 GETREGS/SETREGS，
// 必须使用 GETREGSET/SETREGSET（addr = NT_PRSTATUS）。这里做兼容封装。
#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

static int ptrace_getregs(pid_t pid, struct user_pt_regs *regs)
{
    struct iovec io = { regs, sizeof(*regs) };
    return ptrace(PTRACE_GETREGSET, pid, (void *)(uintptr_t)NT_PRSTATUS, &io) == 0 ? 0 : -1;
}

static int ptrace_setregs(pid_t pid, struct user_pt_regs *regs)
{
    struct iovec io = { regs, sizeof(*regs) };
    return ptrace(PTRACE_SETREGSET, pid, (void *)(uintptr_t)NT_PRSTATUS, &io) == 0 ? 0 : -1;
}

#define RTLD_NOW 0x2

static void die(const char *msg)
{
    fprintf(stderr, "[injector] %s: %s\n", msg, strerror(errno));
}

/* ---------- 远程读写（优先 process_vm_*, 回退 ptrace POKEDATA） ---------- */

static int remote_read(pid_t pid, uintptr_t addr, void *buf, size_t len)
{
    struct iovec local = { buf, len };
    struct iovec remote = { (void *)addr, len };
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (n == (ssize_t)len)
        return 0;

    uint8_t *p = (uint8_t *)buf;
    size_t off = 0;
    while (off < len)
    {
        size_t chunk = (len - off >= 8) ? 8 : (len - off);
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + off), NULL);
        if (word == -1 && errno != 0)
            return -1;
        memcpy(p + off, &word, chunk);
        off += chunk;
    }
    return 0;
}

static int remote_write(pid_t pid, uintptr_t addr, const void *buf, size_t len)
{
    struct iovec local = { (void *)(uintptr_t)buf, len };
    struct iovec remote = { (void *)addr, len };
    ssize_t n = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    if (n == (ssize_t)len)
        return 0;

    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;
    while (off < len)
    {
        size_t chunk = (len - off >= 8) ? 8 : (len - off);
        uint64_t val = 0;
        memcpy(&val, p + off, chunk);
        errno = 0;
        if (ptrace(PTRACE_POKEDATA, pid, (void *)(addr + off), (void *)val) == -1)
            return -1;
        off += chunk;
    }
    return 0;
}

/* ---------- 按包名查找 pid ---------- */

static pid_t find_pid_by_pkg(const char *pkg)
{
    DIR *d = opendir("/proc");
    if (!d)
        return -1;

    struct dirent *e;
    while ((e = readdir(d)) != NULL)
    {
        if (e->d_type != DT_DIR)
            continue;
        pid_t pid = (pid_t)atoi(e->d_name);
        if (pid <= 0)
            continue;

        char cmd[256];
        snprintf(cmd, sizeof(cmd), "/proc/%d/cmdline", pid);
        FILE *f = fopen(cmd, "r");
        if (!f)
            continue;
        char line[256] = {0};
        if (!fgets(line, sizeof(line), f))
        {
            fclose(f);
            continue;
        }
        fclose(f);

        size_t lp = strlen(pkg);
        if (strncmp(line, pkg, lp) == 0)
        {
            closedir(d);
            return pid;
        }
    }
    closedir(d);
    return -1;
}

/* ---------- 解析目标进程 linker64，定位导出符号 ---------- */

static uintptr_t find_linker_base(pid_t pid)
{
    char maps[256];
    snprintf(maps, sizeof(maps), "/proc/%d/maps", pid);
    FILE *f = fopen(maps, "r");
    if (!f)
        return 0;

    char line[512];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), f))
    {
        if (strstr(line, "linker64") != NULL)
        {
            uintptr_t s = 0;
            if (sscanf(line, "%lx-", &s) == 1)
            {
                base = s;
                break;
            }
        }
    }
    fclose(f);
    return base;
}

static uintptr_t find_symbol_remote(pid_t pid, uintptr_t base, const char *name)
{
    Elf64_Ehdr eh;
    if (remote_read(pid, base, &eh, sizeof(eh)))
        return 0;
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0)
        return 0;
    if (eh.e_phnum > 64)
        return 0;

    Elf64_Phdr ph[64];
    if (remote_read(pid, base + eh.e_phoff, ph, sizeof(Elf64_Phdr) * eh.e_phnum))
        return 0;

    uintptr_t dyn_va = 0;
    for (int i = 0; i < eh.e_phnum; i++)
    {
        if (ph[i].p_type == PT_DYNAMIC)
        {
            dyn_va = base + ph[i].p_vaddr;
            break;
        }
    }
    if (!dyn_va)
        return 0;

    uintptr_t symtab = 0, strtab = 0, hashtab = 0;
    for (uintptr_t off = 0;; off += sizeof(Elf64_Dyn))
    {
        Elf64_Dyn d;
        if (remote_read(pid, dyn_va + off, &d, sizeof(d)))
            return 0;
        switch (d.d_tag)
        {
        case DT_SYMTAB: symtab = d.d_un.d_ptr; break;
        case DT_STRTAB: strtab = d.d_un.d_ptr; break;
        case DT_HASH:   hashtab = d.d_un.d_ptr; break;
        case DT_NULL:   goto done;
        default: break;
        }
    }
done:
    if (!symtab || !strtab || !hashtab)
        return 0;

    uint32_t h[2] = {0};
    if (remote_read(pid, hashtab, h, 8))
        return 0;
    uint32_t nsyms = h[1]; // DT_HASH[1] = nchain = 符号数

    for (uint32_t i = 0; i < nsyms; i++)
    {
        Elf64_Sym sym;
        if (remote_read(pid, symtab + (uintptr_t)i * sizeof(Elf64_Sym), &sym, sizeof(sym)))
            return 0;
        if (sym.st_name == 0)
            continue;
        char sname[256] = {0};
        if (remote_read(pid, strtab + sym.st_name, sname, sizeof(sname) - 1))
            return 0;
        if (strcmp(sname, name) == 0)
            return base + sym.st_value; // PIE: 符号值需加基地址
    }
    return 0;
}

static uintptr_t get_dlopen_addr(pid_t pid)
{
    uintptr_t base = find_linker_base(pid);
    if (!base)
        return 0;
    return find_symbol_remote(pid, base, "dlopen");
}

/* ---------- 执行注入 ---------- */

static int do_inject(pid_t pid, const char *so_path, uintptr_t dlopen_addr)
{
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1)
    {
        die("ptrace ATTACH 失败");
        return -1;
    }

    int status = 0;
    waitpid(pid, &status, 0);

    struct user_pt_regs saved, regs;
    if (ptrace_getregs(pid, &saved) == -1)
    {
        die("GETREGS 失败");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return -1;
    }
    regs = saved;

    // 把 .so 路径写到目标栈下方
    uintptr_t sp = saved.sp;
    uintptr_t path_addr = (sp - 0x2000) & ~(uintptr_t)0xfff;
    size_t path_len = strlen(so_path) + 1;
    if (remote_write(pid, path_addr, so_path, path_len))
    {
        die("写入 .so 路径失败");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return -1;
    }

    // 写 brk #0 陷阱作为远程调用的返回点（dlopen 返回后 lr 落到这里触发 SIGTRAP）
    uintptr_t tramp = (path_addr - 0x100) & ~(uintptr_t)0xfff;
    uint8_t brk_insn[4] = {0x00, 0x00, 0x20, 0xd4}; // brk #0 -> 0xd4200000 (LE)
    if (remote_write(pid, tramp, brk_insn, sizeof(brk_insn)))
    {
        die("写入陷阱失败");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return -1;
    }

    regs.regs[0] = path_addr;          // x0 = 路径
    regs.regs[1] = RTLD_NOW;           // x1 = RTLD_NOW
    regs.pc = dlopen_addr;             // pc = dlopen
    regs.regs[30] = tramp;             // lr = 陷阱

    if (ptrace_setregs(pid, &regs) == -1)
    {
        die("SETREGS 失败");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return -1;
    }

    ptrace(PTRACE_CONT, pid, 0, 0);
    waitpid(pid, &status, 0);

    if (ptrace_getregs(pid, &regs) == -1)
    {
        die("GETREGS(返回) 失败");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return -1;
    }

    uintptr_t handle = regs.regs[0];
    fprintf(stderr, "[injector] dlopen 返回 handle = 0x%lx\n", handle);

    // 恢复原始寄存器并脱离
    ptrace_setregs(pid, &saved);
    ptrace(PTRACE_DETACH, pid, 0, 0);

    return handle ? 0 : -1;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "用法:\n"
            "  %s -n <包名> -l <so路径>\n"
            "  %s -p <pid>  -l <so路径>\n"
            "示例:\n"
            "  %s -n com.tencent.tmgp.pubgm -l /data/local/tmp/libUnrealMemoryTools.so\n",
            prog, prog, prog);
}

int main(int argc, char **argv)
{
    const char *pkg = NULL;
    const char *so = NULL;
    pid_t pid = -1;

    for (int i = 1; i < argc; i++)
    {
        if (!strcmp(argv[i], "-n") && i + 1 < argc)
            pkg = argv[++i];
        else if (!strcmp(argv[i], "-p") && i + 1 < argc)
            pid = (pid_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "-l") && i + 1 < argc)
            so = argv[++i];
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help"))
        {
            usage(argv[0]);
            return 0;
        }
    }

    if (!so)
    {
        usage(argv[0]);
        return 1;
    }

    if (pkg && pid < 0)
    {
        pid = find_pid_by_pkg(pkg);
        if (pid < 0)
        {
            fprintf(stderr, "[injector] 未找到包名: %s\n", pkg);
            return 1;
        }
        fprintf(stderr, "[injector] 包名 %s -> pid %d\n", pkg, pid);
    }

    if (pid < 0)
    {
        fprintf(stderr, "[injector] 未指定有效 pid\n");
        return 1;
    }

    uintptr_t dl = get_dlopen_addr(pid);
    if (!dl)
    {
        fprintf(stderr, "[injector] 未能在 linker64 中定位 dlopen\n");
        return 1;
    }
    fprintf(stderr, "[injector] dlopen @ 0x%lx\n", dl);

    int ret = do_inject(pid, so, dl);
    fprintf(stderr, "[injector] %s\n", ret == 0 ? "注入成功" : "注入失败");
    return ret == 0 ? 0 : 1;
}
