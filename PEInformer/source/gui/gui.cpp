#include "gui.h"
#include "NunitoFont.h"
#include "materialSymbolsOutlined.h"

#include "../PEParser/PEParser.h"
#include "../../resource.h"

#include <dwmapi.h>
#pragma comment(lib, "dwmapi.lib")

static ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
static IDXGISwapChain* g_pSwapChain = nullptr;
static bool                     g_SwapChainOccluded = false;
static UINT                     g_ResizeWidth = 0, g_ResizeHeight = 0;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

int WidthWindow  = 800;
int HeightWindow = 500;

bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
void  ImguiStyle(ImGuiStyle& style);
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

void DrawPEParserUI(HWND Handle)
{
    ImGui::PushFont(GUI::MaterialSymbolsFont);

    ImGui::SetCursorPos(ImVec2(80, ImGui::GetCursorPosY() + 10));
    if (ImGui::Button("\ue2c7"))
        PEParser::Path = PEParser::OpenDialogFile().c_str();
    DragAcceptFiles(Handle, true);
    ImGui::PopFont();

    ImGui::SameLine();

    char Buffer[MAX_PATH];
    strcpy_s(Buffer, PEParser::Path.c_str());


    ImGui::SetCursorPos(ImVec2(ImGui::GetCursorPosX(), ImGui::GetCursorPosY() + 10));
    ImGui::PushFont(GUI::NunitoFontHigh);
    ImGui::InputTextMultiline("##Path", Buffer, sizeof(Buffer), ImVec2(ImGui::GetWindowWidth() - 150, 32));
    ImGui::PopFont();

    if (!PEParser::OpenFile())
        return;

    IMAGE_DOS_HEADER* ImageDos = reinterpret_cast<IMAGE_DOS_HEADER*>(PEParser::BuildPE.data());
    if (!ImageDos)
        return;
    else if (ImageDos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        ImGui::SetCursorPos(ImVec2(100, ImGui::GetCursorPosY() + 25));
        ImGui::Text("It isn't a PE file");
        return;
    }
    else if (PEParser::BuildPE.size() < sizeof(IMAGE_DOS_HEADER))
    {
        ImGui::SetCursorPos(ImVec2(100, ImGui::GetCursorPosY() + 25));
        ImGui::Text("The file is corrupted");
        return;
    }

    IMAGE_NT_HEADERS* NTHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(PEParser::BuildPE.data() + ImageDos->e_lfanew);
    if (!NTHeader)
        return;
    else if (NTHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        ImGui::SetCursorPos(ImVec2(100, ImGui::GetCursorPosY() + 25));
        ImGui::Text("It isn't a PE file");
        return;
    }

    bool Is64 = (NTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    ImGui::SetCursorPos(ImVec2(100, ImGui::GetCursorPosY() + 25));
    ImGui::Text("Architecture: %s", Is64 ? "x64, AMD64" : "x32, I386");
    ImGui::SetCursorPosX(100); ImGui::Text("Number of sections: %d", NTHeader->FileHeader.NumberOfSections);


    std::string TypeFile;
    if (NTHeader->FileHeader.Characteristics & IMAGE_FILE_DLL)
        TypeFile = "DLL";
    else
    {
        switch (NTHeader->OptionalHeader.Subsystem)
        {
        case IMAGE_SUBSYSTEM_NATIVE:
        {
            TypeFile = "SYS";
            break;
        }
        case IMAGE_SUBSYSTEM_WINDOWS_GUI:
        {
            TypeFile = "GUI";
            break;
        }
        case IMAGE_SUBSYSTEM_WINDOWS_CUI:
        {
            TypeFile = "CONSOLE";
            break;
        }
        }
    }

    ImGui::SetCursorPosX(100); ImGui::Text("Type file: %s", TypeFile.c_str());

    uint8_t MajorLinkerVersion = 0;
    uint8_t MinorLinkerVersion = 0;
    uint32_t AddressOfEntryPoint = 0;

    if (Is64)
    {
        IMAGE_NT_HEADERS64* NT64 = reinterpret_cast<IMAGE_NT_HEADERS64*>(PEParser::BuildPE.data() + ImageDos->e_lfanew);


        ImGui::SetCursorPosX(100); ImGui::Text("Address Of Entry Point: 0x%08X", NT64->OptionalHeader.AddressOfEntryPoint);
        ImGui::SetCursorPosX(100); ImGui::Text("Base Of Code: 0x%08X", NT64->OptionalHeader.BaseOfCode);
        ImGui::SetCursorPosX(100); ImGui::Text("Image Base: 0x%016llX", NT64->OptionalHeader.ImageBase);
        ImGui::SetCursorPosX(100); ImGui::Text("Section Alignment: 0x%08X", NT64->OptionalHeader.SectionAlignment);

        MajorLinkerVersion = NT64->OptionalHeader.MajorLinkerVersion;
        MinorLinkerVersion = NT64->OptionalHeader.MinorLinkerVersion;
        AddressOfEntryPoint = NT64->OptionalHeader.AddressOfEntryPoint;
    }
    else
    {
        IMAGE_NT_HEADERS32* NT32 = reinterpret_cast<IMAGE_NT_HEADERS32*>(PEParser::BuildPE.data() + ImageDos->e_lfanew);


        ImGui::SetCursorPosX(100); ImGui::Text("Address Of Entry Point: 0x%08X", NT32->OptionalHeader.AddressOfEntryPoint);
        ImGui::SetCursorPosX(100); ImGui::Text("Base Of Code: 0x%08X", NT32->OptionalHeader.BaseOfCode);
        ImGui::SetCursorPosX(100); ImGui::Text("Image Base: 0x%016llX", NT32->OptionalHeader.ImageBase);
        ImGui::SetCursorPosX(100); ImGui::Text("Section Alignment: 0x%08X", NT32->OptionalHeader.SectionAlignment);
        
        MajorLinkerVersion = NT32->OptionalHeader.MajorLinkerVersion;
        MinorLinkerVersion = NT32->OptionalHeader.MinorLinkerVersion;
        AddressOfEntryPoint = NT32->OptionalHeader.AddressOfEntryPoint;
    }

    uint32_t* EndMSDPtr = (uint32_t*)((uint8_t*)PEParser::BuildPE.data() + ImageDos->e_lfanew);
    PEParser::RichHeaderArr = PEParser::ReadRichHeader(EndMSDPtr);

    std::string VersionLinker = PEParser::GetLinkerString();
    if (VersionLinker == "")
        VersionLinker = PEParser::GetLinkerStringWithoutRich(MajorLinkerVersion, MinorLinkerVersion);


    ImGui::SetCursorPosX(100); ImGui::Text("Linker: %s", VersionLinker.c_str());
    ImGui::SetCursorPosX(100); ImGui::Text("Entropy: %.5f", PEParser::Entropy(0, PEParser::BuildPE.size()));


    static std::string DetectPacker = PEParser::ParserSections(NTHeader);
    if (DetectPacker != " ")
    {
        ImGui::SetCursorPosX(100); ImGui::Text("Packer: %s", DetectPacker.c_str());
    }

    static bool HasText = false;
    for (auto& Section : PEParser::SectionsInFile)
    {
        if (Section.Name.find("text") != std::string::npos)
        {
            HasText = true;
            break;
        }
    }

    if (!HasText)
    {
        ImGui::SetCursorPosX(100); ImGui::Text("Packer: [Unknown packer] Doesn't have .text section");
    }

    for (auto& Section : PEParser::SectionsInFile)
    {
        if (Section.Name.find("rsrc") != std::string::npos)
            continue;

        if (Section.Entropy > 7.4)
        {
            ImGui::SetCursorPosX(100); ImGui::Text("Packer: [Unknown packer] High entropy [%s]", Section.Name.c_str());
        }
    }


    ImGui::SetCursorPosX(100);
    if (ImGui::BeginTable("##Sections", 3, ImGuiTableFlags_Resizable | ImGuiTableFlags_NoSavedSettings | ImGuiTableFlags_Borders, ImVec2(400, 1.f)))
    {
        ImGui::TableSetupColumn("Section");
        ImGui::TableSetupColumn("VirtualAddress");
        ImGui::TableSetupColumn("Entropy");
        ImGui::TableHeadersRow();

        for (auto& Section : PEParser::SectionsInFile)
        {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", Section.Name.c_str());
            ImGui::TableNextColumn(); ImGui::Text("0x%08X", Section.VirtualAddress);
            ImGui::TableNextColumn(); ImGui::Text("%.5f", Section.Entropy);
        }
    }
    ImGui::EndTable();
}


int GUI::InitGUI()
{
    ImGui_ImplWin32_EnableDpiAwareness();
    float main_scale = ImGui_ImplWin32_GetDpiScaleForMonitor(::MonitorFromPoint(POINT{ 0, 0 }, MONITOR_DEFAULTTOPRIMARY));

    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, L"PE Informer", nullptr };

    wc.hIcon = LoadIcon(wc.hInstance, MAKEINTRESOURCE(IDI_ICON1));
    wc.hIconSm = LoadIcon(wc.hInstance, MAKEINTRESOURCE(IDI_ICON1));

    ::RegisterClassExW(&wc);
    HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"PE Informer", WS_OVERLAPPEDWINDOW ^ WS_MAXIMIZEBOX, 100, 100, WidthWindow, HeightWindow, nullptr, nullptr, wc.hInstance, nullptr);

    BOOL USE_DARK_MODE = TRUE;
    COLORREF BackgroundColor = RGB(40, 44, 52);
    COLORREF TextColor = RGB(171, 178, 191);
    DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, &BackgroundColor, sizeof(BackgroundColor));
    DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR, &TextColor, sizeof(TextColor));

    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;

    ImGuiStyle& style = ImGui::GetStyle();
    style.ScaleAllSizes(main_scale);
    style.FontScaleDpi = main_scale;

    ImguiStyle(style);

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);
    
    static ImFontConfig config;
    ImFontConfig IconsConfig;
    static const ImWchar IconRanges[] = { 0xe000, 0xf8ff, 0xf0000, 0xffff0, 0 };

    GUI::NunitoFontMedium = ImGui::GetIO().Fonts->AddFontFromMemoryCompressedTTF(nunito_font_compressed_data, nunito_font_compressed_size, 20.5f, &config, ImGui::GetIO().Fonts->GetGlyphRangesCyrillic());
    GUI::NunitoFontHigh = ImGui::GetIO().Fonts->AddFontFromMemoryCompressedTTF(nunito_font_compressed_data, nunito_font_compressed_size, 22.5f, &config, ImGui::GetIO().Fonts->GetGlyphRangesCyrillic());
    GUI::MaterialSymbolsFont = ImGui::GetIO().Fonts->AddFontFromMemoryCompressedBase85TTF(MyIcons_compressed_data_base85, 25.5f, &IconsConfig, IconRanges);

    bool done = false;
    ImGuiWindowFlags Flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoCollapse;
    while (!done)
    {
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
        {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }
        if (done)
            break;

        if (g_SwapChainOccluded && g_pSwapChain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED)
        {
            ::Sleep(10);
            continue;
        }
        g_SwapChainOccluded = false;

        if (g_ResizeWidth != 0 && g_ResizeHeight != 0)
        {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            g_ResizeWidth = g_ResizeHeight = 0;
            CreateRenderTarget();
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        const ImGuiViewport* viewport = ImGui::GetMainViewport();

        ImGui::SetNextWindowPos(viewport->WorkPos);
        ImGui::SetNextWindowSize(viewport->WorkSize);

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        //ImGui::SetNextWindowSize(ImVec2(WidthWindow, HeightWindow));
        ImGui::Begin("##PE Informer", &done, Flags);

        ImGui::SameLine(ImGui::GetWindowWidth() - 80);


        DrawPEParserUI(hwnd);

        ImGui::End();

        ImGui::Render();
        const float clear_color_with_alpha[4] = { clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        HRESULT hr = g_pSwapChain->Present(1, 0);
        g_SwapChainOccluded = (hr == DXGI_STATUS_OCCLUDED);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);

    return 0;
}

// Helper functions

bool CreateDeviceD3D(HWND hWnd)
{
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    //createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
    HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res == DXGI_ERROR_UNSUPPORTED) // Try high-performance WARP software driver if hardware is not available.
        res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res != S_OK)
        return false;

    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D()
{
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

void CreateRenderTarget()
{
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

void CleanupRenderTarget()
{
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

// Forward declare message handler from imgui_impl_win32.cpp
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Win32 message handler
// You can read the io.WantCaptureMouse, io.WantCaptureKeyboard flags to tell if dear imgui wants to use your inputs.
// - When io.WantCaptureMouse is true, do not dispatch mouse input data to your main application, or clear/overwrite your copy of the mouse data.
// - When io.WantCaptureKeyboard is true, do not dispatch keyboard input data to your main application, or clear/overwrite your copy of the keyboard data.
// Generally you may always pass all inputs to dear imgui, and hide them from your application based on those two flags.
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
    {
        if (wParam == SIZE_MINIMIZED)
            return 0;
        g_ResizeWidth = (UINT)LOWORD(lParam); // Queue resize
        g_ResizeHeight = (UINT)HIWORD(lParam);
        return 0;
    }
    case WM_SYSCOMMAND:
    {
        if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
            return 0;
        break;
    }
    case WM_DESTROY:
    {
        ::PostQuitMessage(0);
        return 0;
    }
    case WM_DROPFILES:
    {
        HDROP hDrop = (HDROP)wParam;
        char FilePath[MAX_PATH];

        PEParser::Path = "";

        UINT DragQuery = DragQueryFile(hDrop, 0xFFFFFFFF, NULL, NULL);
        for (UINT i = 0; i < DragQuery; i++)
        {
            DragQueryFileA(hDrop, i, FilePath, MAX_PATH);
        }

        PEParser::Path += FilePath;

        DragFinish(hDrop);
        return 0;
    }
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}

void  ImguiStyle(ImGuiStyle& style)
{
    // Borders
    style.WindowBorderSize = 3.0f;
    
    // Rounding
    style.FrameRounding = 3.0f;
    style.PopupRounding = 3.0f;
    style.ScrollbarRounding = 3.0f;
    style.GrabRounding = 3.0f;
    
    constexpr auto ToRGBA = [](unsigned int argb) constexpr
        {
            ImVec4 color{};
            color.x = ((argb >> 16) & 0xFF) / 255.0f;
            color.y = ((argb >> 8) & 0xFF) / 255.0f;
            color.z = (argb & 0xFF) / 255.0f;
            color.w = ((argb >> 24) & 0xFF) / 255.0f;
            return color;
        };
    
    
    auto colors{ style.Colors };
    colors[ImGuiCol_Text] = ToRGBA(0xFFABB2BF);
    colors[ImGuiCol_TextDisabled] = ToRGBA(0xFF565656);
    colors[ImGuiCol_WindowBg] = ToRGBA(0xFF282C34);
    colors[ImGuiCol_ChildBg] = ToRGBA(0xFF21252B);
    colors[ImGuiCol_PopupBg] = ToRGBA(0xFF2E323A);
    colors[ImGuiCol_Border] = ToRGBA(0xFF2E323A);
    colors[ImGuiCol_BorderShadow] = ToRGBA(0x00000000);
    colors[ImGuiCol_FrameBg] = colors[ImGuiCol_ChildBg];
    colors[ImGuiCol_FrameBgHovered] = ToRGBA(0xFF484C52);
    colors[ImGuiCol_FrameBgActive] = ToRGBA(0xFF54575D);
    colors[ImGuiCol_TitleBg] = colors[ImGuiCol_WindowBg];
    colors[ImGuiCol_TitleBgActive] = colors[ImGuiCol_FrameBgActive];
    colors[ImGuiCol_TitleBgCollapsed] = ToRGBA(0x8221252B);
    colors[ImGuiCol_MenuBarBg] = colors[ImGuiCol_ChildBg];
    colors[ImGuiCol_ScrollbarBg] = colors[ImGuiCol_PopupBg];
    colors[ImGuiCol_ScrollbarGrab] = ToRGBA(0xFF3E4249);
    colors[ImGuiCol_ScrollbarGrabHovered] = ToRGBA(0xFF484C52);
    colors[ImGuiCol_ScrollbarGrabActive] = ToRGBA(0xFF54575D);
    colors[ImGuiCol_CheckMark] = colors[ImGuiCol_Text];
    colors[ImGuiCol_SliderGrab] = ToRGBA(0xFF353941);
    colors[ImGuiCol_SliderGrabActive] = ToRGBA(0xFF7A7A7A);
    colors[ImGuiCol_Button] = colors[ImGuiCol_SliderGrab];
    colors[ImGuiCol_ButtonHovered] = colors[ImGuiCol_FrameBgActive];
    colors[ImGuiCol_ButtonActive] = colors[ImGuiCol_ScrollbarGrabActive];
    colors[ImGuiCol_Header] = colors[ImGuiCol_ChildBg];
    colors[ImGuiCol_HeaderHovered] = ToRGBA(0xFF353941);
    colors[ImGuiCol_HeaderActive] = colors[ImGuiCol_FrameBgActive];
    colors[ImGuiCol_Separator] = colors[ImGuiCol_FrameBgActive];
    colors[ImGuiCol_SeparatorHovered] = ToRGBA(0xFF3E4452);
    colors[ImGuiCol_SeparatorActive] = colors[ImGuiCol_SeparatorHovered];
    colors[ImGuiCol_ResizeGrip] = colors[ImGuiCol_Separator];
    colors[ImGuiCol_ResizeGripHovered] = colors[ImGuiCol_SeparatorHovered];
    colors[ImGuiCol_ResizeGripActive] = colors[ImGuiCol_SeparatorActive];
    colors[ImGuiCol_InputTextCursor] = ToRGBA(0xFF528BFF);
    colors[ImGuiCol_TabHovered] = colors[ImGuiCol_HeaderHovered];
    colors[ImGuiCol_Tab] = colors[ImGuiCol_FrameBgActive];
    colors[ImGuiCol_TabSelected] = colors[ImGuiCol_HeaderHovered];
    colors[ImGuiCol_TabSelectedOverline] = colors[ImGuiCol_HeaderActive];
    colors[ImGuiCol_TabDimmedSelectedOverline] = ImVec4{ 0.50f, 0.50f, 0.50f, 0.00f };
    colors[ImGuiCol_PlotLines] = ImVec4{ 0.61f, 0.61f, 0.61f, 1.00f };
    colors[ImGuiCol_PlotLinesHovered] = ImVec4{ 1.00f, 0.43f, 0.35f, 1.00f };
    colors[ImGuiCol_PlotHistogram] = ImVec4{ 0.90f, 0.70f, 0.00f, 1.00f };
    colors[ImGuiCol_PlotHistogramHovered] = ImVec4{ 1.00f, 0.60f, 0.00f, 1.00f };
    colors[ImGuiCol_TableHeaderBg] = colors[ImGuiCol_ChildBg];
    colors[ImGuiCol_TableBorderStrong] = colors[ImGuiCol_SliderGrab];
    colors[ImGuiCol_TableBorderLight] = colors[ImGuiCol_FrameBgActive];
    colors[ImGuiCol_TableRowBg] = ImVec4{ 0.00f, 0.00f, 0.00f, 0.00f };
    colors[ImGuiCol_TableRowBgAlt] = ImVec4{ 1.00f, 1.00f, 1.00f, 0.06f };
    colors[ImGuiCol_TextLink] = ToRGBA(0xFF3F94CE);
    colors[ImGuiCol_TextSelectedBg] = ToRGBA(0xFF243140);
    colors[ImGuiCol_TreeLines] = colors[ImGuiCol_Text];
    colors[ImGuiCol_DragDropTarget] = colors[ImGuiCol_Text];
    colors[ImGuiCol_NavCursor] = colors[ImGuiCol_TextLink];
    colors[ImGuiCol_NavWindowingHighlight] = colors[ImGuiCol_Text];
    colors[ImGuiCol_NavWindowingDimBg] = ImVec4{ 0.80f, 0.80f, 0.80f, 0.20f };
    colors[ImGuiCol_ModalWindowDimBg] = ToRGBA(0xC821252B);
}