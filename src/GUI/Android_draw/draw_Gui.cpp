#include "draw.h"
#include "draw_overlay.h"

#include "My_font/zh_Font.h"
#include "My_font/fontawesome-brands.h"
#include "My_font/fontawesome-regular.h"
#include "My_font/fontawesome-solid.h"
#include "My_font/gui_icon.h"
   
#include "My_icon/pic_ZhenAiKun_png.h"

extern void RenderAutoUEDumpPanel(bool *main_thread_flag);

bool permeate_record = false;
bool permeate_record_ini = false;
struct Last_ImRect LastCoordinate = {0, 0, 0, 0};


std::unique_ptr<AndroidImgui> graphics;
ANativeWindow *window = NULL; 
android::ANativeWindowCreator::DisplayInfo displayInfo;// 屏幕信息
ImGuiWindow *g_window = NULL;// 窗口信息
int abs_ScreenX = 0, abs_ScreenY = 0;// 绝对屏幕X _ Y
int native_window_screen_x = 0, native_window_screen_y = 0;

TextureInfo Aekun_image{};

ImFont* zh_font = NULL;
ImFont* icon_font_0 = NULL;
ImFont* icon_font_1 = NULL;
ImFont* icon_font_2 = NULL;



bool M_Android_LoadFont(float SizePixels) {
    ImGuiIO &io = ImGui::GetIO();
    
	static const ImWchar icons_ranges[] = {ICON_MIN_FA, ICON_MAX_FA, 0};
    ImFontConfig icons_config;
    icons_config.MergeMode = true;
    icons_config.PixelSnapH = true;
    icons_config.OversampleH = 2.0;
    icons_config.OversampleV = 2.0;		
    icons_config.SizePixels = SizePixels;
	::icon_font_0 = io.Fonts->AddFontFromMemoryCompressedTTF((const void *)&font_awesome_brands_compressed_data, sizeof(font_awesome_brands_compressed_data), 0.0f, &icons_config, icons_ranges);
	::icon_font_1 = io.Fonts->AddFontFromMemoryCompressedTTF((const void *)&font_awesome_regular_compressed_data, sizeof(font_awesome_regular_compressed_data), 0.0f, &icons_config, icons_ranges);
	::icon_font_2 = io.Fonts->AddFontFromMemoryCompressedTTF((const void *)&font_awesome_solid_compressed_data, sizeof(font_awesome_solid_compressed_data), 0.0f, &icons_config, icons_ranges);

    if (io.Fonts->Fonts.empty()) {
        io.Fonts->AddFontDefault();
    }
    return true;
}

void init_My_drawdata(float scale) {
    ImGuiIO &io = ImGui::GetIO();
    ImGui::StyleColorsDark();

    if (scale <= 0.0f) {
        float minDim = (displayInfo.height > 0 && displayInfo.width > 0)
                           ? (displayInfo.height < displayInfo.width ? displayInfo.height : displayInfo.width)
                           : 1080.0f;
        scale = minDim / 1080.0f;
        if (scale < 0.85f) scale = 0.85f;
        if (scale > 2.2f)  scale = 2.2f;
    }

    float fontSize = 24.0f * scale;
    if (fontSize < 18.0f) fontSize = 18.0f;

    ImFont *sysFont = ImGui::My_Android_LoadSystemFont(fontSize);
    if (sysFont) {
        io.FontDefault = sysFont;
    }
    M_Android_LoadFont(fontSize);

    ImGuiStyle &style = ImGui::GetStyle();
    style.ScaleAllSizes(scale);

    // 针对触屏优化的间距与圆角（增大触控热区，避免误触）
    style.TouchExtraPadding = ImVec2(4.0f * scale, 4.0f * scale);
    style.FramePadding = ImVec2(10.0f * scale, 6.0f * scale);
    style.ItemSpacing = ImVec2(10.0f * scale, 7.0f * scale);
    style.ScrollbarSize = 24.0f * scale;
    style.GrabMinSize = 20.0f * scale;
    style.WindowRounding = 10.0f * scale;
    style.FrameRounding = 6.0f * scale;
    style.PopupRounding = 6.0f * scale;

    if (graphics) {
        ::Aekun_image = graphics->LoadTextureFromMemory((void *)picture_ZhenAiKun_PNG_H, sizeof(picture_ZhenAiKun_PNG_H));
    }
}


void screen_config() {
    ::displayInfo = android::ANativeWindowCreator::GetDisplayInfo();
}

void drawBegin() {
    if (::permeate_record_ini) {
        LastCoordinate.Pos_x = ::g_window->Pos.x;
        LastCoordinate.Pos_y = ::g_window->Pos.y;
        LastCoordinate.Size_x = ::g_window->Size.x;
        LastCoordinate.Size_y = ::g_window->Size.y;

        graphics->Shutdown();
        android::ANativeWindowCreator::Destroy(::window);
        ::window = android::ANativeWindowCreator::Create("AImGui", native_window_screen_x, native_window_screen_y, permeate_record);
        graphics->Init_Render(::window, native_window_screen_x, native_window_screen_y);
        ::init_My_drawdata(); //初始化绘制数据
    } 


    static uint32_t orientation = -1;
    screen_config();
    if (orientation != displayInfo.orientation) {
        orientation = displayInfo.orientation;
        Touch::setOrientation((int)displayInfo.orientation);
        if (g_window != NULL) {
            g_window->Pos.x = 40;
            g_window->Pos.y = 30;        
        }        
    }
}


void Layout_tick_UI(bool *main_thread_flag) {
    {
        ImGuiIO &io = ImGui::GetIO();
        float dispW = (io.DisplaySize.x > 0.0f) ? io.DisplaySize.x : 2400.0f;
        float dispH = (io.DisplaySize.y > 0.0f) ? io.DisplaySize.y : 1080.0f;
        float winW = (dispW > dispH) ? std::min(dispW * 0.78f, 1300.0f) : std::min(dispW * 0.94f, 1000.0f);
        float winH = (dispW > dispH) ? std::min(dispH * 0.88f, 850.0f) : std::min(dispH * 0.80f, 1200.0f);
        if (winW < 360.0f) winW = dispW - 20.0f;
        if (winH < 280.0f) winH = dispH - 20.0f;

        ImGui::SetNextWindowSize(ImVec2(winW, winH), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowPos(ImVec2(30.0f, 25.0f), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowBgAlpha(0.92f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 12.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.2f);
        // 使用 imgui 原生标题栏：左侧折叠箭头(收起菜单) + 拖动标题栏移动 + 右上角关闭
        ImGui::Begin("UnrealMemoryTools 控制台", main_thread_flag,
                     ImGuiWindowFlags_None);
        if (::permeate_record_ini) {
            ImGui::SetWindowPos({LastCoordinate.Pos_x, LastCoordinate.Pos_y});
            ImGui::SetWindowSize({LastCoordinate.Size_x, LastCoordinate.Size_y});
            permeate_record_ini = false;
        }

        // 触控方向快速校准（支持 90° / 270° / 1:1 单击切换）
        ImGui::TextDisabled("触控方向:");
        ImGui::SameLine();
        ImGui::RadioButton("90°(口在右)", &OverlayUI::g_touchMode, 1);
        ImGui::SameLine();
        ImGui::RadioButton("270°(口在左)", &OverlayUI::g_touchMode, 2);
        ImGui::SameLine();
        ImGui::RadioButton("1:1直通", &OverlayUI::g_touchMode, 0);
        ImGui::Separator();

        RenderAutoUEDumpPanel(main_thread_flag);
        g_window = ImGui::GetCurrentWindow();
        ImGui::End();
        ImGui::PopStyleVar(2);
    }
}

