// ============================================================================
//  EGL Overlay 实现（GOT hook + GLES overlay 渲染）
// ============================================================================
#include "draw_overlay.h"

#include "draw.h"            // Layout_tick_UI / init_My_drawdata / graphics
#include "Android_Graphics/OpenGLGraphics.h"
#include "imgui_impl_opengl3.h"
#include "my_imgui_impl_android.h"
#include "../../Utils/Logger.hpp"  // LOGI/LOGE（kEXECUTABLE 下写文件 + printf）
#include "../../UE/UEMemory.hpp"   // UEMemory::kMgr（DIRECT 模式）
#include "../native_surface/ANativeWindowCreator.h"  // GetDisplayInfo（屏幕物理分辨率）

#include <android/input.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>
#include <GLES3/gl3.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <atomic>
#include <string>
#include <vector>
#include <thread>

// 自动探针 + Dump（由 executable.cpp 提供）
extern void RunAutoProbeDump();

// aarch64 重定位类型（<elf.h> 未必带，安全起见自备）
#ifndef R_AARCH64_GLOB_DAT
#define R_AARCH64_GLOB_DAT 1025
#endif
#ifndef R_AARCH64_JUMP_SLOT
#define R_AARCH64_JUMP_SLOT 1026
#endif

namespace
{
    std::atomic<bool> g_installed{false};
    std::atomic<bool> g_ready{false};
    bool g_menu_open = true;

    EGLDisplay g_dpy = EGL_NO_DISPLAY;
    EGLSurface g_srf = EGL_NO_SURFACE;
    int g_win_w = 0, g_win_h = 0;

    // ================= 符号 GOT hook =================
    // 只 hook 游戏渲染核心模块（调用 eglSwapBuffers 的位置在 libUE4 等），
    // 跳过腾讯保护库（libPx*）与系统库，避免触发反作弊完整性校验。
    bool IsRenderModule(const std::string &path)
    {
        return path.find("libUE4.so") != std::string::npos ||
               path.find("libUnreal.so") != std::string::npos ||
               path.find("libclient.so") != std::string::npos ||
               path.find("libShadowTrackerExtra.so") != std::string::npos;
    }

    bool HookPltSymbol(const char *module, const char *symName,
                       void *hookFn, void **origFn)
    {
        // 使用本地内存后端（DIRECT 进程内直读）。
        // 注意：不能依赖全局 UEMemory::kMgr —— overlay 安装发生在 ExecuteProbe 之前，
        // kMgr 此时尚未 initialize，_pMemOp 为空会导致 ElfScanner 全部解析失败（有效模块=0）。
        KittyMemoryMgr localMgr;
        if (!localMgr.initialize(getpid(), EK_MEM_OP_DIRECT, false))
        {
            LOGE("[OV] 本地内存后端初始化失败");
            return false;
        }

        void *handle = dlopen(module, RTLD_NOW);
        if (!handle)
        {
            LOGE("[OV] dlopen(%s) 失败", module);
            return false;
        }
        void *target = dlsym(handle, symName);
        if (!target)
        {
            LOGE("[OV] dlsym(%s) 失败", symName);
            return false;
        }
        if (origFn)
            *origFn = target;
        LOGI("[OV] %s::%s = %p", module, symName, target);

        const auto maps = KittyMemoryEx::getAllMaps(getpid());
        bool anyHooked = false;
        int relocTotal = 0;
        int scannedMods = 0, validMods = 0;

        for (const auto &m : maps)
        {
            if (m.pathname.find(".so") == std::string::npos)
                continue;
            if (!IsRenderModule(m.pathname))
                continue;   // 只处理游戏渲染核心模块
            scannedMods++;

            ElfScanner es = localMgr.elfScanner.createWithBase(m.startAddress);
            if (!es.isValid())
                continue;
            validMods++;

            const uintptr_t bias = es.loadBias();
            const uintptr_t strtab = es.stringTable();
            const uintptr_t symtab = es.symbolTable();
            if (!bias || !strtab || !symtab)
                continue;

            // 收集重定位表（DT_JMPREL -> .rela.plt，DT_RELA -> .rela.dyn）
            struct RelocTable
            {
                uintptr_t addr = 0;
                size_t size = 0;
            };
            RelocTable plt, dyn;

            for (const auto &d : es.dynamics())
            {
                if (d.d_tag == DT_JMPREL)
                    plt.addr = bias + d.d_un.d_ptr;
                else if (d.d_tag == DT_PLTRELSZ)
                    plt.size = d.d_un.d_val;
                else if (d.d_tag == DT_RELA)
                    dyn.addr = bias + d.d_un.d_ptr;
                else if (d.d_tag == DT_RELASZ)
                    dyn.size = d.d_un.d_val;
            }

            const RelocTable tables[2] = {plt, dyn};
            for (const auto &tbl : tables)
            {
                if (!tbl.addr || tbl.size < sizeof(Elf64_Rela))
                    continue;
                if (tbl.size > 16 * 1024 * 1024)   // 越界保护
                    continue;

                const size_t count = tbl.size / sizeof(Elf64_Rela);
                std::vector<Elf64_Rela> rels(count);
                if (!localMgr.readMem(tbl.addr, rels.data(), tbl.size))
                    continue;

                for (const auto &rel : rels)
                {
                    const unsigned type = (unsigned)(rel.r_info & 0xffffffff);
                    if (type != R_AARCH64_JUMP_SLOT && type != R_AARCH64_GLOB_DAT)
                        continue;

                    const size_t symIdx = (size_t)(rel.r_info >> 32);
                    Elf64_Sym sym{};
                    if (!localMgr.readMem(symtab + (uintptr_t)symIdx * sizeof(Elf64_Sym),
                                      &sym, sizeof(sym)))
                        continue;
                    if (!sym.st_name)
                        continue;

                    char name[128] = {0};
                    if (!localMgr.readMem(strtab + sym.st_name, name, sizeof(name) - 1))
                        continue;
                    if (strcmp(name, symName) != 0)
                        continue;

                    // GOT 槽 = bias + r_offset
                    const uintptr_t slot = bias + rel.r_offset;
                    uintptr_t cur = 0;
                    localMgr.readMem(slot, &cur, sizeof(cur));

                    // 不校验 cur == target：部分模块 lazy binding（槽未解析，指向 PLT stub），
                    // 直接改写槽即可，hook 函数内部会调用 dlsym 保存的原函数。
                    LOGI("[OV] 匹配 %s %s @ %p (cur=%p -> hook=%p)", m.pathname.c_str(),
                         symName, (void *)slot, (void *)cur, hookFn);

                    // 解除保护后写入；写完恢复【原页权限】而非强制只读——
                    // libUE4 的 GOT 页原为可写（懒绑定需继续写 GOT），
                    // 若强制 PROT_READ 会导致下一次懒绑定写 GOT 时 SEGV_ACCERR。
                    const long pgsz = sysconf(_SC_PAGESIZE);
                    const uintptr_t pg = slot & ~(uintptr_t)(pgsz - 1);
                    mprotect((void *)pg, pgsz, PROT_READ | PROT_WRITE);
                    *(void **)slot = hookFn;
                    __builtin___clear_cache((char *)slot, (char *)slot + sizeof(void *));

                    const auto slotMap = KittyMemoryEx::getAddressMap(maps, slot);
                    int origProt = PROT_NONE;
                    if (slotMap.readable) origProt |= PROT_READ;
                    if (slotMap.writeable) origProt |= PROT_WRITE;
                    if (slotMap.executable) origProt |= PROT_EXEC;
                    mprotect((void *)pg, pgsz, origProt);

                    anyHooked = true;
                    relocTotal++;
                }
            }
        }

        LOGI("[OV] %s hook 完成，改写槽数 = %d (扫描 .so 模块 %d / 有效 %d)",
             symName, relocTotal, scannedMods, validMods);
        return anyHooked;
    }

    // ================= overlay 触摸校准 =================
    // 核心原理（与参考 main_8.cpp 一致）:
    //   scaleX = egl_surface_width  / screen_physical_width
    //   scaleY = egl_surface_height / screen_physical_height
    // AMotionEvent_getX/Y 返回的是屏幕物理坐标 (0~physW, 0~physH)，
    // ImGui DisplaySize = EGL Surface 尺寸 (可能是降采样的，如 1520x1080)。
    // 必须用可靠方式获取屏幕物理分辨率，而不是"动态学习"——后者在用户未
    // 碰到屏幕最边缘之前永远不准。
    static int g_screenPhysW = 0;
    static int g_screenPhysH = 0;

    // 从 /sys/class/graphics/fb0/virtual_size 读取帧缓冲分辨率（最可靠）
    static bool ReadFbVirtualSize(int *outW, int *outH)
    {
        FILE *fp = fopen("/sys/class/graphics/fb0/virtual_size", "r");
        if (!fp) return false;
        int w = 0, h = 0;
        if (fscanf(fp, "%d,%d", &w, &h) == 2 && w > 0 && h > 0)
        {
            *outW = w;
            *outH = h;
            fclose(fp);
            return true;
        }
        fclose(fp);
        return false;
    }

    // 从 /sys/class/graphics/fb0/modes 读取（部分设备不提供 virtual_size）
    static bool ReadFbModes(int *outW, int *outH)
    {
        FILE *fp = fopen("/sys/class/graphics/fb0/modes", "r");
        if (!fp) return false;
        char buf[256] = {0};
        if (fgets(buf, sizeof(buf), fp))
        {
            // 格式通常为 "U:2400x1080p-60" 或 "S:1080x2400p-0"
            int w = 0, h = 0;
            char *p = strstr(buf, ":");
            if (p && sscanf(p + 1, "%dx%d", &w, &h) == 2 && w > 0 && h > 0)
            {
                *outW = w;
                *outH = h;
                fclose(fp);
                return true;
            }
        }
        fclose(fp);
        return false;
    }

    // 综合获取当前屏幕物理分辨率（按横屏游戏方向输出: W >= H）
    static void ResolveScreenPhysicalSize(int *outW, int *outH)
    {
        int w = 0, h = 0;

        // 方法1: sysfs framebuffer (最通用，不需要特殊权限)
        if (ReadFbVirtualSize(&w, &h) && w > 0 && h > 0)
        {
            // virtual_size 可能包含双缓冲高度 (如 2400x2160 = 2400x1080*2)，取较小值
            if (h > w * 2) h = h / 2;
            if (w > h * 2) w = w / 2;
            // 确保横屏: W >= H
            *outW = (w >= h) ? w : h;
            *outH = (w >= h) ? h : w;
            LOGI("[OV] 屏幕物理分辨率 (fb0/virtual_size): %dx%d", *outW, *outH);
            return;
        }

        // 方法2: sysfs fb modes
        if (ReadFbModes(&w, &h) && w > 0 && h > 0)
        {
            *outW = (w >= h) ? w : h;
            *outH = (w >= h) ? h : w;
            LOGI("[OV] 屏幕物理分辨率 (fb0/modes): %dx%d", *outW, *outH);
            return;
        }

        // 方法3: SurfaceComposer (需要一定系统权限，注入场景下可能成功也可能失败)
        auto disp = android::ANativeWindowCreator::GetDisplayInfo();
        if (disp.width > 0 && disp.height > 0)
        {
            w = (disp.width >= disp.height) ? disp.width : disp.height;
            h = (disp.width >= disp.height) ? disp.height : disp.width;
            // 检查是否是硬编码的 2400x1080 默认值（GetDisplayInfo 失败时返回）
            // 如果是且与 EGL surface 差异极大，不信任
            if (w != 2400 || h != 1080 || (g_win_w > 0 && abs(w - g_win_w) < g_win_w / 2))
            {
                *outW = w;
                *outH = h;
                LOGI("[OV] 屏幕物理分辨率 (SurfaceComposer): %dx%d", *outW, *outH);
                return;
            }
        }

        // 方法4: 最终回退 - 假设触摸坐标与 EGL Surface 1:1 (无缩放)
        // 这在渲染分辨率 == 屏幕分辨率的设备上是正确的
        *outW = g_win_w;
        *outH = g_win_h;
        LOGI("[OV] 屏幕物理分辨率 (回退=EGL Surface): %dx%d", *outW, *outH);
    }

    void OverlayInputTransform(float *x, float *y)
    {
        if (!x || !y || g_win_w <= 0 || g_win_h <= 0)
            return;

        // scale = EGL_surface / 屏幕物理 (与 main_8.cpp 的 g_gl_width / g_cached_view_width 完全等价)
        float scaleX = 1.0f;
        float scaleY = 1.0f;
        if (g_screenPhysW > 0 && g_screenPhysH > 0)
        {
            scaleX = (float)g_win_w / (float)g_screenPhysW;
            scaleY = (float)g_win_h / (float)g_screenPhysH;
        }

        *x = *x * scaleX;
        *y = *y * scaleY;

        if (*x < 0.0f) *x = 0.0f;
        if (*x > (float)g_win_w) *x = (float)g_win_w;
        if (*y < 0.0f) *y = 0.0f;
        if (*y > (float)g_win_h) *y = (float)g_win_h;
    }

    void OverlayInit(EGLDisplay dpy, EGLSurface srf)
    {
        int w = 0, h = 0;
        eglQuerySurface(dpy, srf, EGL_WIDTH, &w);
        eglQuerySurface(dpy, srf, EGL_HEIGHT, &h);
        if (w <= 0 || h <= 0)
            return;

        g_dpy = dpy;
        g_srf = srf;
        g_win_w = w;
        g_win_h = h;

        // 获取屏幕物理分辨率用于触摸坐标缩放
        ResolveScreenPhysicalSize(&g_screenPhysW, &g_screenPhysH);
        LOGI("[OV] EGL Surface=%dx%d, 屏幕物理=%dx%d, scaleX=%.4f, scaleY=%.4f",
             g_win_w, g_win_h, g_screenPhysW, g_screenPhysH,
             g_screenPhysW > 0 ? (float)g_win_w / g_screenPhysW : 1.0f,
             g_screenPhysH > 0 ? (float)g_win_h / g_screenPhysH : 1.0f);

        ImGui::CreateContext();
        ImGuiIO &io = ImGui::GetIO();
        // 逻辑系 = 渲染 surface 尺寸（等比不拉伸，字体清晰，点位精准）
        io.DisplaySize = ImVec2((float)g_win_w, (float)g_win_h);
        io.DisplayFramebufferScale = ImVec2(1.f, 1.f);
        io.IniFilename = nullptr;
        io.LogFilename = nullptr;

        ImGui_ImplOpenGL3_Init("#version 300 es");
        My_ImGui_ImplAndroid_Init(nullptr);
        My_ImGui_ImplAndroid_SetInputTransform(OverlayInputTransform);

        // 计算当前 Overlay 分辨率下的 DPI 缩放比例
        float minDim = (g_win_w < g_win_h) ? (float)g_win_w : (float)g_win_h;
        float dpiScale = minDim / 1080.0f;
        if (dpiScale < 0.85f) dpiScale = 0.85f;
        if (dpiScale > 2.2f)  dpiScale = 2.2f;

        // 复用当前 GL context 做纹理加载（不创建自己的 EGL context）
        ::graphics = std::make_unique<OpenGLGraphics>();
        init_My_drawdata(dpiScale);

        g_ready = true;
        LOGI("[OV] overlay 初始化完成 %dx%d (屏幕=%dx%d, scale=%.2f, 复用游戏 GL context)",
             w, h, g_screenPhysW, g_screenPhysH, dpiScale);

        // 自动执行探针 + SDK Dump（后台线程，菜单实时显示进度）
        std::thread(RunAutoProbeDump).detach();
    }

    void OverlayFrame()
    {
        if (!g_ready)
            return;

        My_ImGui_ImplAndroid_NewFrame();
        ImGui_ImplOpenGL3_NewFrame();

        // 逻辑系固定为 surface 尺寸（输入变换已完成等比缩放+居中）
        ImGuiIO &io = ImGui::GetIO();
        io.DisplaySize = ImVec2((float)g_win_w, (float)g_win_h);
        io.DisplayFramebufferScale = ImVec2(1.f, 1.f);

        ImGui::NewFrame();

        Layout_tick_UI(&g_menu_open);

        ImGui::Render();
        glViewport(0, 0, g_win_w, g_win_h);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    }

    // ================= hook 回调 =================
    static EGLBoolean (*real_eglSwapBuffers)(EGLDisplay, EGLSurface) = nullptr;

    EGLBoolean hook_eglSwapBuffers(EGLDisplay dpy, EGLSurface srf)
    {
        if (!g_ready)
        {
            // 游戏渲染线程 GL context 就绪后初始化一次
            if (eglGetCurrentContext() != EGL_NO_CONTEXT)
                OverlayInit(dpy, srf);
        }
        else
        {
            OverlayFrame();
        }
        return real_eglSwapBuffers(dpy, srf);
    }

    static int32_t (*real_AInputQueue_getEvent)(AInputQueue *, AInputEvent **) = nullptr;

    int32_t hook_AInputQueue_getEvent(AInputQueue *queue, AInputEvent **outEvent)
    {
        const int32_t ret = real_AInputQueue_getEvent(queue, outEvent);
        if (ret == 0 && outEvent && *outEvent && g_ready)
        {
            // 触摸转发给 ImGui（菜单可交互）
            My_ImGui_ImplAndroid_HandleInputEvent(*outEvent);

            // 注意：不能像金铲铲(Unity)那样用 WantCaptureMouse 置空事件截断——
            // UE4 对 null 事件不健壮，会把 null 传给 AInputQueue_finishEvent，
            // libandroid.so 内部解引用空指针直接 SEGV (fault=0x0)（实测 m-capture 崩溃）。
            // 因此只转发、绝不吞事件；游戏照常收到触摸（点菜单时游戏也响应，可接受）。
        }
        return ret;
    }
}  // namespace

namespace OverlayUI
{
    bool Install()
    {
        if (g_installed)
            return true;

        if (!HookPltSymbol("libEGL.so", "eglSwapBuffers",
                           (void *)hook_eglSwapBuffers,
                           (void **)&real_eglSwapBuffers))
        {
            LOGE("[OV] hook eglSwapBuffers 失败，无法叠加菜单");
            return false;
        }

        // 输入 hook：只转发不吞事件（TP 检测吞事件行为），让菜单可拖拽/点击
        HookPltSymbol("libandroid.so", "AInputQueue_getEvent",
                      (void *)hook_AInputQueue_getEvent,
                      (void **)&real_AInputQueue_getEvent);

        g_installed = true;
        LOGI("[OV] EGL overlay 安装成功：菜单将绘制在游戏画面上（输入=只转发不吞）");
        return true;
    }

    bool IsActive()
    {
        return g_installed;
    }
}  // namespace OverlayUI
