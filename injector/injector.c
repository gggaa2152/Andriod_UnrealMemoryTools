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
//    injector -n <包名> -l /data/1/libUnrealMemoryTools.so
//    injector -p <pid>  -l /data/1/libUnrealMemoryTools.so
//    injector            (自动扫描并注入第一个虚幻游戏进程)
//
//  需要 root（ptrace attach 非子进程）。
//  默认加载路径: /data/1/libUnrealMemoryTools.so
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

// 构建戳：每次改动后重新编译，设备上跑起来第一行会打印它，便于确认是否是最新二进制
#define INJECTOR_BUILD "2026-08-26d-safe-readv"

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

/* ---------- 自动识别虚幻游戏进程 ---------- */

// 检测进程 maps 中是否加载了 libUE4.so / libUnreal.so
static int has_unreal_lib(pid_t pid)
{
    char maps[256];
    snprintf(maps, sizeof(maps), "/proc/%d/maps", pid);
    FILE *f = fopen(maps, "r");
    if (!f)
        return 0;

    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f))
    {
        if (strstr(line, "libUE4.so") || strstr(line, "libUnreal.so"))
        {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

// 读取进程包名（/proc/pid/cmdline 第一段）
static int get_proc_pkg(pid_t pid, char *out, size_t outsz)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "/proc/%d/cmdline", pid);
    FILE *f = fopen(cmd, "r");
    if (!f)
        return -1;

    char line[256] = {0};
    if (!fgets(line, sizeof(line), f))
    {
        fclose(f);
        return -1;
    }
    fclose(f);

    size_t len = strcspn(line, "\0"); // cmdline 以 \0 分隔
    if (len == 0)
        return -1;
    if (len >= outsz)
        len = outsz - 1;
    memcpy(out, line, len);
    out[len] = 0;
    return 0;
}

// 自动扫描所有进程，收集加载了 UE 动态库的候选，返回数量（最多 maxn）
static int find_ue_candidates(pid_t *pids, char (*pkgs)[256], int maxn)
{
    DIR *d = opendir("/proc");
    if (!d)
        return 0;

    struct dirent *e;
    int n = 0;
    while ((e = readdir(d)) != NULL && n < maxn)
    {
        if (e->d_type != DT_DIR)
            continue;
        pid_t pid = (pid_t)atoi(e->d_name);
        if (pid <= 1)
            continue;
        if (!has_unreal_lib(pid))
            continue;

        char pkg[256] = {0};
        if (get_proc_pkg(pid, pkg, sizeof(pkg)) != 0 || pkg[0] == 0)
            snprintf(pkg, sizeof(pkg), "pid-%d", pid);

        pids[n] = pid;
        memcpy(pkgs[n], pkg, strlen(pkg) + 1);
        n++;
    }
    closedir(d);
    return n;
}

/* ---------- 解析目标进程 linker64，定位导出符号 ---------- */

// 在目标 maps 中按库名（子串）查找第一个匹配模块的基址
static uintptr_t find_module_base_by_name(pid_t pid, const char *name)
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
        if (strstr(line, name) != NULL)
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

static uintptr_t find_linker_base(pid_t pid)
{
    return find_module_base_by_name(pid, "linker64");
}

// GNU hash（DT_GNU_HASH 使用的变体 djb2）
static uint32_t gnu_hash(const char *s)
{
    uint32_t h = 5381;
    for (unsigned char c = (unsigned char)*s; c != 0; c = (unsigned char)*s++)
        h = h * 33 + c;
    return h;
}

// 从 GNU hash 表精确计算 dynsym 总数：
//   nsyms = max(buckets[]) 后再沿 chain 走到链尾（LSB 置位）。
// 仅用于确定线性扫描上界，避免依赖易错的 bloom 过滤。
static uint32_t gnu_nsyms(pid_t pid, uintptr_t gnuhash)
{
    uint32_t hdr[4] = {0};
    if (remote_read(pid, gnuhash, hdr, 16))
        return 0;
    uint32_t nbuckets   = hdr[0];
    uint32_t symoffset  = hdr[1];
    uint32_t bloom_size = hdr[2];
    if (bloom_size == 0 || nbuckets == 0)
        return 0;

    uintptr_t buckets_va = gnuhash + 16 + (uintptr_t)bloom_size * 8;
    uint32_t nsyms = symoffset;
    for (uint32_t i = 0; i < nbuckets; i++)
    {
        uint32_t b = 0;
        if (remote_read(pid, buckets_va + (uintptr_t)i * 4, &b, 4))
            return 0;
        if (b > nsyms)
            nsyms = b;
    }
    if (nsyms < symoffset)
        return 0;

    uintptr_t chain_va = buckets_va + (uintptr_t)nbuckets * 4;
    uint32_t idx = nsyms;
    for (uint32_t step = 0; step < 4000000; step++)
    {
        uint32_t c = 0;
        if (remote_read(pid, chain_va + (uintptr_t)(idx - symoffset) * 4, &c, 4))
            return 0;
        if (c & 1)
            return idx + 1; // 链尾，idx 是最后一个符号
        idx++;
    }
    return 0;
}

// 在远程进程的 dynsym 中按名查找符号，支持 DT_HASH 与 DT_GNU_HASH 两套哈希表
static uintptr_t find_symbol_remote(pid_t pid, uintptr_t base, const char *name)
{
    uintptr_t load_bias = base;
    Elf64_Ehdr eh;
    if (remote_read(pid, load_bias, &eh, sizeof(eh)))
        return 0;
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0)
        return 0;
    if (eh.e_phnum > 64)
        return 0;

    Elf64_Phdr ph[64];
    if (remote_read(pid, load_bias + eh.e_phoff, ph, sizeof(Elf64_Phdr) * eh.e_phnum))
        return 0;

    // 计算 load_bias：动态表里的 DT_SYMTAB/DT_STRTAB/DT_GNU_HASH 等 d_ptr 是
    // “相对模块基址 0 的虚拟地址”，运行时真实地址 = load_bias + d_ptr。
    // Android 的 PIE .so 首个 PT_LOAD 的 p_vaddr 通常为 0，故 load_bias == base；
    // 这里按规范精确计算，避免直接拿 d_ptr 当地址去读（那样只会读到低位垃圾）。
    for (int i = 0; i < eh.e_phnum; i++)
    {
        if (ph[i].p_type == PT_LOAD)
        {
            load_bias = base - ph[i].p_vaddr;
            break;
        }
    }

    uintptr_t dyn_va = 0;
    for (int i = 0; i < eh.e_phnum; i++)
    {
        if (ph[i].p_type == PT_DYNAMIC)
        {
            dyn_va = load_bias + ph[i].p_vaddr;
            break;
        }
    }
    if (!dyn_va)
        return 0;

    uintptr_t symtab = 0, strtab = 0, hashtab = 0, gnuhash = 0;
    for (uintptr_t off = 0;; off += sizeof(Elf64_Dyn))
    {
        Elf64_Dyn d;
        if (remote_read(pid, dyn_va + off, &d, sizeof(d)))
            return 0;
        switch (d.d_tag)
        {
        case DT_SYMTAB:    symtab = load_bias + d.d_un.d_ptr; break;
        case DT_STRTAB:    strtab = load_bias + d.d_un.d_ptr; break;
        case DT_HASH:      hashtab = load_bias + d.d_un.d_ptr; break;
        case DT_GNU_HASH:  gnuhash = load_bias + d.d_un.d_ptr; break;
        case DT_NULL:      goto done;
        default: break;
        }
    }
done:
    fprintf(stderr, "[injector]   dynsym: symtab=0x%lx strtab=0x%lx DT_HASH=%d DT_GNU_HASH=%d\n",
            symtab, strtab, hashtab != 0, gnuhash != 0);
    if (!symtab || !strtab)
        return 0;

    // 计算 dynsym 数量（线性扫描上界）：
    //   1) DT_HASH.nchain（最准确）
    //   2) GNU hash 推断（bucket 最大值 + 沿 chain 走到链尾）
    //   3) 回退：包含 symtab 的 PT_LOAD 段末尾估算
    uint32_t nsyms = 0;
    if (hashtab)
    {
        uint32_t h[2] = {0};
        if (remote_read(pid, hashtab, h, 8) == 0)
            nsyms = h[1]; // nchain == 符号数
    }
    uint32_t nsyms_gnu = gnuhash ? gnu_nsyms(pid, gnuhash) : 0;
    if (nsyms_gnu > nsyms)
        nsyms = nsyms_gnu; // 取 DT_HASH / GNU 二者较大者，避免数量算小漏掉符号
    if (nsyms == 0)
    {
        for (int i = 0; i < eh.e_phnum; i++)
        {
            if (ph[i].p_type == PT_LOAD)
            {
                uintptr_t va  = load_bias + ph[i].p_vaddr;
                uintptr_t end = va + ph[i].p_filesz;
                if (symtab >= va && symtab < end)
                {
                    nsyms = (uint32_t)((end - symtab) / sizeof(Elf64_Sym));
                    break;
                }
            }
        }
    }
    if (nsyms == 0)
        nsyms = 1; // 保底至少扫一个，避免没拿到数量就直接放弃
    fprintf(stderr, "[injector]   nsyms = %u\n", nsyms);

    // 线性扫描全部 dynsym（不依赖 bloom/chain，最稳健）
    for (uint32_t i = 0; i < nsyms; i++)
    {
        Elf64_Sym sym;
        if (remote_read(pid, symtab + (uintptr_t)i * sizeof(Elf64_Sym), &sym, sizeof(sym)))
            return 0;
        if (sym.st_name == 0 || sym.st_shndx == 0) // 跳过空名 / 未定义符号
            continue;
        char sname[256] = {0};
        if (remote_read(pid, strtab + sym.st_name, sname, sizeof(sname) - 1))
            return 0;
        if (strcmp(sname, name) == 0)
        {
            fprintf(stderr, "[injector]   found(linear) %s @ 0x%lx\n", name, load_bias + sym.st_value);
            return load_bias + sym.st_value; // 运行时地址 = load_bias + st_value
        }
    }

    return 0;
}

// dlopen 定位结果：addr + 调用约定标记
//   need_caller=0：标准 2 参 dlopen(const char*, int)，x2 忽略（填 0）
//   need_caller=1：linker 内部 __dl_dlopen(filename, flags, caller_addr)，x2 必须给调用方地址
typedef struct { uintptr_t addr; int need_caller; } dlopen_t;

// 兜底：扫描目标进程所有已加载模块（不仅限于 libc/linker），找第一个导出的 dlopen
// 系列符号。用于应对某些 ROM 把 dlopen 放在非常规模块的情况。
static dlopen_t find_dlopen_in_all_modules(pid_t pid)
{
    char maps[256];
    snprintf(maps, sizeof(maps), "/proc/%d/maps", pid);
    FILE *f = fopen(maps, "r");
    if (!f)
        return (dlopen_t){0, 0};

    char line[512];
    char seen[128][256]; // 已扫描过的模块路径去重
    int nseen = 0;
    const char *names[] = {"dlopen", "__dl_dlopen", "__loader_dlopen", NULL};

    while (fgets(line, sizeof(line), f))
    {
        uintptr_t start = 0;
        if (sscanf(line, "%lx-", &start) != 1)
            continue;

        // 取该行末尾的文件路径
        char *path = NULL;
        for (char *q = line; *q; q++)
            if (*q == ' ')
                path = q + 1;
        if (!path || *path == '\n' || *path == 0)
            continue;
        // 去掉末尾换行/空格
        size_t plen = strlen(path);
        while (plen > 0 && (path[plen - 1] == '\n' || path[plen - 1] == ' '))
            path[--plen] = 0;
        // 只关心共享库 / linker
        if (!strstr(path, ".so") && !strstr(path, "linker"))
            continue;

        // 去重：同一模块只扫一次（取首个映射，即最低地址 = 模块基址）
        int dup = 0;
        for (int i = 0; i < nseen; i++)
            if (strcmp(seen[i], path) == 0) { dup = 1; break; }
        if (dup)
            continue;
        if (nseen < 128)
        {
            strncpy(seen[nseen], path, sizeof(seen[0]) - 1);
            seen[nseen][sizeof(seen[0]) - 1] = 0;
            nseen++;
        }

        for (int k = 0; names[k]; k++)
        {
            uintptr_t a = find_symbol_remote(pid, start, names[k]);
            if (a)
            {
                fclose(f);
                dlopen_t r = {a, (k == 0) ? 0 : 1};
                fprintf(stderr, "[injector] %s(模块 %s) = 0x%lx\n", names[k], path, a);
                return r;
            }
        }
    }
    fclose(f);
    return (dlopen_t){0, 0};
}

static dlopen_t get_dlopen_addr(pid_t pid)
{
    dlopen_t r = {0, 0};

    // 候选（按优先级）：先标准 2 参 dlopen，再回退 linker 内部实现
    struct cand { const char *mod; const char *name; int need_caller; };
    struct cand tries[] = {
        {"libc.so",          "dlopen",         0},
        {"libdl.so",         "dlopen",         0},
        {"libdl_android.so", "dlopen",         0},
        {"linker64",         "dlopen",         1},
        {"linker64",         "__dl_dlopen",    1},
        {"linker64",         "__loader_dlopen",1},
        {NULL, NULL, 0},
    };

    for (int i = 0; tries[i].mod; i++)
    {
        uintptr_t b;
        if (strcmp(tries[i].mod, "linker64") == 0)
            b = find_linker_base(pid);
        else
            b = find_module_base_by_name(pid, tries[i].mod);
        if (!b)
            continue;
        fprintf(stderr, "[injector] try %s (\"%s\") base = 0x%lx\n", tries[i].mod, tries[i].name, b);
        uintptr_t a = find_symbol_remote(pid, b, tries[i].name);
        if (a)
        {
            fprintf(stderr, "[injector] %s(%s) = 0x%lx\n", tries[i].name, tries[i].mod, a);
            r.addr = a;
            r.need_caller = tries[i].need_caller;
            return r;
        }
    }

    // 兜底：扫描目标进程全部已加载模块
    fprintf(stderr, "[injector] 候选库均未命中，扫描全部已加载模块...\n");
    dlopen_t all = find_dlopen_in_all_modules(pid);
    if (all.addr)
        return all;

    return r;
}

/* ---------- 执行注入 ---------- */

static int do_inject(pid_t pid, const char *so_path)
{
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1)
    {
        die("ptrace ATTACH 失败");
        return -1;
    }

    int status = 0;
    waitpid(pid, &status, 0);

    // attach 之后跨进程内存读才稳（部分设备未 attach 时 process_vm_readv 被 SELinux 拦截）
    dlopen_t dl = get_dlopen_addr(pid);
    if (!dl.addr)
    {
        fprintf(stderr, "[injector] 未能在 linker64 / libdl / libc 中定位 dlopen\n");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return -1;
    }
    fprintf(stderr, "[injector] dlopen @ 0x%lx (need_caller=%d)\n", dl.addr, dl.need_caller);

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
    regs.regs[2] = dl.need_caller ? tramp : 0; // x2 = caller_addr（__dl_dlopen 需要；标准 dlopen 忽略）
    regs.pc = dl.addr;                 // pc = dlopen
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
            "  %s                      (自动扫描并注入第一个虚幻游戏进程)\n"
            "  %s -n <包名>            (按包名注入)\n"
            "  %s -p <pid>             (按 pid 注入)\n"
            "  -l <so路径>             (可选, 默认 /data/1/libUnrealMemoryTools.so)\n"
            "示例:\n"
            "  %s\n"
            "  %s -n com.tencent.tmgp.pubgm\n"
            "  %s -l /data/1/libUnrealMemoryTools.so\n",
            prog, prog, prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
    fprintf(stderr, "[injector] build " INJECTOR_BUILD "\n");

    const char *pkg = NULL;
    const char *so = NULL;
    pid_t pid = -1;

    int watch = 0;
    int start_app = 0;

    for (int i = 1; i < argc; i++)
    {
        if (!strcmp(argv[i], "-w") || !strcmp(argv[i], "--watch"))
            watch = 1;
        else if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--start"))
            start_app = 1;
        else if (!strcmp(argv[i], "-n") && i + 1 < argc)
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
        so = "/data/1/libUnrealMemoryTools.so";

    // 如果指定了启动游戏，直接调用系统命令拉起游戏，并强制进入 watch 模式
    if (start_app && pkg) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "monkey -p %s -c android.intent.category.LAUNCHER 1 > /dev/null 2>&1", pkg);
        fprintf(stderr, "[injector] 正在自动唤起游戏: %s\n", pkg);
        system(cmd);
        watch = 1; 
    } else if (start_app && !pkg) {
        fprintf(stderr, "[injector] 警告: 使用 -s 参数必须同时通过 -n 指定包名！\n");
        return 1;
    }

    if (watch) {
        fprintf(stderr, "[injector] 开启守候模式，等待游戏进程启动...\n");
        while (pid < 0) {
            if (pkg) {
                pid = find_pid_by_pkg(pkg);
            } else {
                pid_t cands[32];
                char cpkgs[32][256];
                if (find_ue_candidates(cands, cpkgs, 32) > 0) {
                    pid = cands[0];
                    fprintf(stderr, "[injector] 发现目标: %s (pid=%d)\n", cpkgs[0], pid);
                }
            }
            if (pid < 0) {
                usleep(50000); // 50ms 极速轮询
            }
        }
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

    // 未指定包名 / pid：自动扫描并识别虚幻游戏进程
    if (pid < 0)
    {
        pid_t cands[32];
        char cpkgs[32][256];
        int nc = find_ue_candidates(cands, cpkgs, 32);
        if (nc == 0)
        {
            fprintf(stderr, "[injector] 未找到任何加载 libUE4.so/libUnreal.so 的进程\n");
            return 1;
        }
        fprintf(stderr, "[injector] 发现 %d 个虚幻游戏进程:\n", nc);
        for (int i = 0; i < nc; i++)
            fprintf(stderr, "  [%d] pid=%d pkg=%s\n", i, cands[i], cpkgs[i]);
        pid = cands[0];
        fprintf(stderr, "[injector] 自动选择注入: pid=%d pkg=%s\n", pid, cpkgs[0]);
    }

    int ret = do_inject(pid, so);
    fprintf(stderr, "[injector] %s\n", ret == 0 ? "注入成功" : "注入失败");
    return ret == 0 ? 0 : 1;
}
