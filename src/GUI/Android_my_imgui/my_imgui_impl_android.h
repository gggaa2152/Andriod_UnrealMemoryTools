#pragma once

#include "imgui.h"

struct ANativeWindow;
struct AInputEvent;

// 触摸坐标变换回调（overlay 模式：物理屏触摸坐标 -> 渲染 surface 坐标系）
typedef void (*InputTransformFn)(float *x, float *y);

bool My_ImGui_ImplAndroid_Init(ANativeWindow *window);

void My_ImGui_ImplAndroid_SetInputTransform(InputTransformFn fn);

int32_t My_ImGui_ImplAndroid_HandleInputEvent(AInputEvent *input_event);

int32_t My_ImGui_ImplAndroid_HandleInputEvent_old(AInputEvent *input_event);

void My_ImGui_ImplAndroid_Shutdown();

void My_ImGui_ImplAndroid_NewFrame(bool resize = false);