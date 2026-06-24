#include "gui.hpp"
#include "internals.h"
#include "imgui.h"
#include <sstream>
#include <iomanip>
#include <fstream>
#include <algorithm>
#include <future>
#include <chrono>

unsigned long active_pid = 0;
std::wstring active_process_name = L"None";

static int current_tab = 0;
static char process_filter[128] = "";
static std::vector<process_info> cached_processes;
static unsigned long last_process_refresh = 0;

static std::vector<memory_region> cached_regions;
static unsigned long last_memory_pid = 0;

static std::vector<module_info> cached_modules;
static unsigned long last_module_pid = 0;
static int selected_module_idx = -1;
static unsigned char* selected_module_base = nullptr;
static char manual_base_address[32] = "";
static char dump_path[512] = "";
static std::string dump_status = "";
static bool dump_success = false;

static bool show_warning_popup = false;
static unsigned long pid_to_terminate = 0;
static std::wstring name_to_terminate = L"";

static char mem_protect_address[32] = "";
static char mem_protect_size[32] = "";
static int mem_protect_choice = 2;
static std::string mem_protect_status = "";
static bool mem_protect_success = false;

static char mem_write_address[32] = "";
static char mem_write_bytes[256] = "";
static std::string mem_write_status = "";
static bool mem_write_success = false;

static char mem_scan_start[32] = "";
static char mem_scan_size[32] = "";
static char mem_scan_pattern[256] = "";
static char mem_scan_mask[256] = "";
static std::string mem_scan_status = "";
static bool mem_scan_success = false;
static int memory_type_filter = 0;
static bool scan_running = false;
static std::future<unsigned char*> scan_future;

static std::vector<thread_info> cached_threads;
static std::vector<handle_info> cached_handles;
static unsigned long last_thread_pid = 0;
static unsigned long last_handle_pid = 0;
static unsigned long last_thread_refresh = 0;
static unsigned long last_handle_refresh = 0;
static char handle_filter[128] = "";

static const unsigned long protection_values[] = {
    PAGE_NOACCESS,
    PAGE_READONLY,
    PAGE_READWRITE,
    PAGE_WRITECOPY,
    PAGE_EXECUTE,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY
};

static const char* protection_names[] = {
    "PAGE_NOACCESS",
    "PAGE_READONLY",
    "PAGE_READWRITE",
    "PAGE_WRITECOPY",
    "PAGE_EXECUTE",
    "PAGE_EXECUTE_READ",
    "PAGE_EXECUTE_READWRITE",
    "PAGE_EXECUTE_WRITECOPY"
};

static unsigned long long parse_hex_value(const std::string& input) {
    std::string clean = input;
    if (clean.starts_with("0x") || clean.starts_with("0X")) {
        clean = clean.substr(2);
    }
    unsigned long long val = 0;
    std::stringstream ss;
    ss << std::hex << clean;
    if (ss >> val) {
        return val;
    }
    return 0;
}

static std::vector<unsigned char> parse_hex_string(const std::string& input) {
    std::vector<unsigned char> bytes;
    std::string clean;
    for (char c : input) {
        if (std::isxdigit(static_cast<unsigned char>(c))) {
            clean += c;
        }
    }
    if (clean.size() % 2 != 0) {
        return bytes;
    }
    for (size_t i = 0; i < clean.size(); i += 2) {
        std::string byte_str = clean.substr(i, 2);
        unsigned char byte_val = static_cast<unsigned char>(std::stoul(byte_str, nullptr, 16));
        bytes.push_back(byte_val);
    }
    return bytes;
}

static bool case_insensitive_strstr(const std::string& str, const std::string& sub) {
    auto it = std::search(
        str.begin(), str.end(),
        sub.begin(), sub.end(),
        [](char ch1, char ch2) { return std::tolower(static_cast<unsigned char>(ch1)) == std::tolower(static_cast<unsigned char>(ch2)); }
    );
    return it != str.end();
}

static bool is_critical_process(const std::wstring& name, unsigned long pid) {
    if (pid <= 4) {
        return true;
    }
    std::wstring lower_name = name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(std::tolower(static_cast<int>(c)));
    });
    return lower_name == L"system" ||
           lower_name == L"registry" ||
           lower_name == L"smss.exe" ||
           lower_name == L"csrss.exe" ||
           lower_name == L"wininit.exe" ||
           lower_name == L"services.exe" ||
           lower_name == L"lsass.exe" ||
           lower_name == L"winlogon.exe" ||
           lower_name == L"svchost.exe" ||
           lower_name == L"explorer.exe";
}

static std::string to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) {
        return "";
    }
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    std::string str_to(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &str_to[0], size_needed, nullptr, nullptr);
    return str_to;
}

static std::string format_size(unsigned long long bytes) {
    if (bytes >= 1024 * 1024 * 1024) {
        std::stringstream ss;
        ss << std::fixed << std::setprecision(2) << (double)bytes / (1024 * 1024 * 1024) << " GB";
        return ss.str();
    }
    if (bytes >= 1024 * 1024) {
        std::stringstream ss;
        ss << std::fixed << std::setprecision(2) << (double)bytes / (1024 * 1024) << " MB";
        return ss.str();
    }
    if (bytes >= 1024) {
        std::stringstream ss;
        ss << std::fixed << std::setprecision(2) << (double)bytes / 1024 << " KB";
        return ss.str();
    }
    return std::to_string(bytes) + " B";
}

static std::string protect_to_string(unsigned long protect) {
    std::string result;
    unsigned long base_protect = protect & 0xFF;
    switch (base_protect) {
        case PAGE_NOACCESS: result = "PAGE_NOACCESS"; break;
        case PAGE_READONLY: result = "PAGE_READONLY"; break;
        case PAGE_READWRITE: result = "PAGE_READWRITE"; break;
        case PAGE_WRITECOPY: result = "PAGE_WRITECOPY"; break;
        case PAGE_EXECUTE: result = "PAGE_EXECUTE"; break;
        case PAGE_EXECUTE_READ: result = "PAGE_EXECUTE_READ"; break;
        case PAGE_EXECUTE_READWRITE: result = "PAGE_EXECUTE_READWRITE"; break;
        case PAGE_EXECUTE_WRITECOPY: result = "PAGE_EXECUTE_WRITECOPY"; break;
        default: result = "UNKNOWN"; break;
    }
    if (protect & PAGE_GUARD) {
        result += " | PAGE_GUARD";
    }
    if (protect & PAGE_NOCACHE) {
        result += " | PAGE_NOCACHE";
    }
    if (protect & PAGE_WRITECOMBINE) {
        result += " | PAGE_WRITECOMBINE";
    }
    return result;
}

static std::string type_to_string(unsigned long type) {
    switch (type) {
        case MEM_IMAGE: return "MEM_IMAGE";
        case MEM_MAPPED: return "MEM_MAPPED";
        case MEM_PRIVATE: return "MEM_PRIVATE";
        default: return "UNKNOWN";
    }
}

void apply_custom_theme() {
    ImGuiStyle& style = ImGui::GetStyle();
    ImVec4* colors = style.Colors;

    style.WindowPadding = ImVec2(15.0f, 15.0f);
    style.FramePadding = ImVec2(8.0f, 6.0f);
    style.CellPadding = ImVec2(8.0f, 6.0f);
    style.ItemSpacing = ImVec2(10.0f, 10.0f);
    style.ItemInnerSpacing = ImVec2(8.0f, 6.0f);
    style.TouchExtraPadding = ImVec2(0.0f, 0.0f);
    style.IndentSpacing = 21.0f;
    style.ScrollbarSize = 14.0f;
    style.GrabMinSize = 12.0f;

    style.WindowBorderSize = 1.0f;
    style.ChildBorderSize = 1.0f;
    style.PopupBorderSize = 1.0f;
    style.FrameBorderSize = 1.0f;
    style.TabBorderSize = 1.0f;

    style.WindowRounding = 8.0f;
    style.ChildRounding = 6.0f;
    style.FrameRounding = 6.0f;
    style.PopupRounding = 6.0f;
    style.ScrollbarRounding = 8.0f;
    style.GrabRounding = 6.0f;
    style.TabRounding = 6.0f;

    ImVec4 accent_color = ImVec4(0.000f, 0.470f, 0.831f, 1.000f);
    ImVec4 border_primary = ImVec4(0.200f, 0.200f, 0.200f, 1.000f);
    ImVec4 border_active = ImVec4(0.239f, 0.239f, 0.239f, 1.000f);
    ImVec4 bg_color = ImVec4(0.117f, 0.117f, 0.117f, 1.000f);
    ImVec4 bg_secondary = ImVec4(0.125f, 0.125f, 0.125f, 1.000f);
    ImVec4 hover_color = ImVec4(0.176f, 0.176f, 0.176f, 1.000f);
    ImVec4 text_primary = ImVec4(1.000f, 1.000f, 1.000f, 1.000f);
    ImVec4 text_inactive = ImVec4(0.627f, 0.627f, 0.627f, 1.000f);

    colors[ImGuiCol_Text] = text_primary;
    colors[ImGuiCol_TextDisabled] = text_inactive;
    colors[ImGuiCol_WindowBg] = bg_color;
    colors[ImGuiCol_ChildBg] = bg_secondary;
    colors[ImGuiCol_PopupBg] = bg_secondary;
    colors[ImGuiCol_Border] = border_primary;
    colors[ImGuiCol_BorderShadow] = ImVec4(0.000f, 0.000f, 0.000f, 0.000f);
    colors[ImGuiCol_FrameBg] = bg_secondary;
    colors[ImGuiCol_FrameBgHovered] = hover_color;
    colors[ImGuiCol_FrameBgActive] = border_active;
    colors[ImGuiCol_TitleBg] = bg_secondary;
    colors[ImGuiCol_TitleBgActive] = bg_secondary;
    colors[ImGuiCol_TitleBgCollapsed] = bg_secondary;
    colors[ImGuiCol_MenuBarBg] = bg_secondary;
    colors[ImGuiCol_ScrollbarBg] = bg_color;
    colors[ImGuiCol_ScrollbarGrab] = border_active;
    colors[ImGuiCol_ScrollbarGrabHovered] = hover_color;
    colors[ImGuiCol_ScrollbarGrabActive] = accent_color;
    colors[ImGuiCol_CheckMark] = accent_color;
    colors[ImGuiCol_SliderGrab] = accent_color;
    colors[ImGuiCol_SliderGrabActive] = accent_color;
    colors[ImGuiCol_Button] = bg_secondary;
    colors[ImGuiCol_ButtonHovered] = hover_color;
    colors[ImGuiCol_ButtonActive] = border_active;
    colors[ImGuiCol_Header] = hover_color;
    colors[ImGuiCol_HeaderHovered] = hover_color;
    colors[ImGuiCol_HeaderActive] = border_active;
    colors[ImGuiCol_Separator] = border_primary;
    colors[ImGuiCol_SeparatorHovered] = border_active;
    colors[ImGuiCol_SeparatorActive] = accent_color;
    colors[ImGuiCol_ResizeGrip] = border_primary;
    colors[ImGuiCol_ResizeGripHovered] = border_active;
    colors[ImGuiCol_ResizeGripActive] = accent_color;
    colors[ImGuiCol_Tab] = bg_secondary;
    colors[ImGuiCol_TabHovered] = hover_color;
    colors[ImGuiCol_TabActive] = border_active;
    colors[ImGuiCol_TabUnfocused] = bg_secondary;
    colors[ImGuiCol_TabUnfocusedActive] = border_active;
    colors[ImGuiCol_PlotLines] = accent_color;
    colors[ImGuiCol_PlotLinesHovered] = accent_color;
    colors[ImGuiCol_PlotHistogram] = accent_color;
    colors[ImGuiCol_PlotHistogramHovered] = accent_color;
    colors[ImGuiCol_TableHeaderBg] = bg_secondary;
    colors[ImGuiCol_TableBorderStrong] = border_primary;
    colors[ImGuiCol_TableBorderLight] = border_primary;
    colors[ImGuiCol_TableRowBg] = bg_color;
    colors[ImGuiCol_TableRowBgAlt] = bg_secondary;
    colors[ImGuiCol_TextSelectedBg] = hover_color;
    colors[ImGuiCol_DragDropTarget] = accent_color;
    colors[ImGuiCol_NavHighlight] = accent_color;
    colors[ImGuiCol_NavWindowingHighlight] = accent_color;
    colors[ImGuiCol_NavWindowingDimBg] = ImVec4(0.000f, 0.000f, 0.000f, 0.500f);
    colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.000f, 0.000f, 0.000f, 0.500f);
}

void render_ui() {
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->Pos);
    ImGui::SetNextWindowSize(viewport->Size);
    ImGui::SetNextWindowViewport(viewport->ID);

    ImGuiWindowFlags window_flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus;

    if (!ImGui::Begin("MainWindow", nullptr, window_flags)) {
        ImGui::End();
        return;
    }

    ImGui::BeginChild("Header", ImVec2(0, 50), true);
    ImGui::TextColored(ImVec4(0.376f, 0.722f, 1.000f, 1.000f), "Memory and Process Manipulation Tool");
    ImGui::SameLine(ImGui::GetWindowWidth() - 350.0f);
    if (active_pid != 0) {
        ImGui::Text("Active Process: %s (%lu)", to_utf8(active_process_name).c_str(), active_pid);
    } else {
        ImGui::Text("Active Process: None");
    }
    ImGui::EndChild();

    ImGui::BeginChild("Sidebar", ImVec2(180, 0), true);

    bool tab_0_active = (current_tab == 0);
    if (tab_0_active) {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.000f, 0.470f, 0.831f, 0.200f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.000f, 0.470f, 0.831f, 0.300f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.000f, 0.470f, 0.831f, 0.400f));
    }
    if (ImGui::Button("Process List", ImVec2(-1, 40))) current_tab = 0;
    if (tab_0_active) {
        ImGui::PopStyleColor(3);
    }

    ImGui::Spacing();

    bool tab_1_active = (current_tab == 1);
    if (tab_1_active) {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.000f, 0.470f, 0.831f, 0.200f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.000f, 0.470f, 0.831f, 0.300f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.000f, 0.470f, 0.831f, 0.400f));
    }
    if (ImGui::Button("Memory Scanner", ImVec2(-1, 40))) current_tab = 1;
    if (tab_1_active) {
        ImGui::PopStyleColor(3);
    }

    ImGui::Spacing();

    bool tab_2_active = (current_tab == 2);
    if (tab_2_active) {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.000f, 0.470f, 0.831f, 0.200f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.000f, 0.470f, 0.831f, 0.300f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.000f, 0.470f, 0.831f, 0.400f));
    }
    if (ImGui::Button("PE Dumper", ImVec2(-1, 40))) current_tab = 2;
    if (tab_2_active) {
        ImGui::PopStyleColor(3);
    }

    ImGui::EndChild();

    ImGui::SameLine();

    ImGui::BeginChild("Content", ImVec2(0, 0), true);
    if (current_tab == 0) {
        unsigned long current_time = GetTickCount();
        if (cached_processes.empty() || current_time - last_process_refresh > 2000) {
            cached_processes = get_active_processes();
            last_process_refresh = current_time;
        }

        float avail_width = ImGui::GetContentRegionAvail().x;
        ImGui::BeginChild("ProcessListSection", ImVec2(avail_width * 0.45f - 5.0f, 0), true);

        ImGui::InputText("Search Process", process_filter, sizeof(process_filter));
        if (active_pid != 0) {
            ImGui::SameLine();
            if (ImGui::Button("End Task")) {
                pid_to_terminate = active_pid;
                name_to_terminate = active_process_name;
                if (is_critical_process(name_to_terminate, pid_to_terminate)) {
                    show_warning_popup = true;
                } else {
                    terminate_process(pid_to_terminate);
                    active_pid = 0;
                    active_process_name = L"None";
                    cached_processes.clear();
                }
            }
        }
        ImGui::Spacing();

        if (ImGui::BeginTable("ProcessTable", 2, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersInnerV, ImVec2(0, -1))) {
            ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableSetupColumn("Process Name", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            for (const auto& process : cached_processes) {
                std::string name_utf8 = to_utf8(process.name);
                if (process_filter[0] != '\0' && !case_insensitive_strstr(name_utf8, process_filter)) {
                    continue;
                }

                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);

                bool is_selected = (active_pid == process.id);
                std::string pid_str = std::to_string(process.id);
                if (ImGui::Selectable(pid_str.c_str(), is_selected, ImGuiSelectableFlags_SpanAllColumns)) {
                    active_pid = process.id;
                    active_process_name = process.name;
                }

                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(name_utf8.c_str());
            }
            ImGui::EndTable();
        }
        ImGui::EndChild();

        ImGui::SameLine();

        ImGui::BeginChild("ProcessDetailsSection", ImVec2(0, 0), true);
        if (active_pid == 0) {
            ImGui::TextColored(ImVec4(0.961f, 0.961f, 0.969f, 0.500f), "Select a process from the list to view details.");
        } else {
            if (ImGui::BeginTabBar("DetailsTabBar")) {
                if (ImGui::BeginTabItem("Threads")) {
                    if (active_pid != last_thread_pid || cached_threads.empty() || current_time - last_thread_refresh > 3000) {
                        cached_threads = get_process_threads(active_pid);
                        last_thread_pid = active_pid;
                        last_thread_refresh = current_time;
                    }
                    if (ImGui::Button("Refresh Threads")) {
                        cached_threads = get_process_threads(active_pid);
                        last_thread_refresh = current_time;
                    }
                    ImGui::Spacing();
                    if (ImGui::BeginTable("ThreadsTable", 2, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersInnerV, ImVec2(0, -1))) {
                        ImGui::TableSetupColumn("TID", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                        ImGui::TableSetupColumn("Base Priority", ImGuiTableColumnFlags_WidthStretch);
                        ImGui::TableHeadersRow();

                        for (const auto& thr : cached_threads) {
                            ImGui::TableNextRow();
                            ImGui::TableSetColumnIndex(0);
                            ImGui::Text("%lu", thr.id);
                            ImGui::TableSetColumnIndex(1);
                            ImGui::Text("%ld", thr.priority);
                        }
                        ImGui::EndTable();
                    }
                    ImGui::EndTabItem();
                }

                if (ImGui::BeginTabItem("Handles")) {
                    if (active_pid != last_handle_pid || cached_handles.empty() || current_time - last_handle_refresh > 5000) {
                        cached_handles = get_process_handles(active_pid);
                        last_handle_pid = active_pid;
                        last_handle_refresh = current_time;
                    }
                    ImGui::InputText("Filter Handles", handle_filter, sizeof(handle_filter));
                    ImGui::SameLine();
                    if (ImGui::Button("Refresh Handles")) {
                        cached_handles = get_process_handles(active_pid);
                        last_handle_refresh = current_time;
                    }
                    ImGui::Spacing();
                    if (ImGui::BeginTable("HandlesTable", 3, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersInnerV, ImVec2(0, -1))) {
                        ImGui::TableSetupColumn("Handle", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 120.0f);
                        ImGui::TableSetupColumn("Name / Path", ImGuiTableColumnFlags_WidthStretch);
                        ImGui::TableHeadersRow();

                        for (const auto& hnd : cached_handles) {
                            std::string type_utf8 = to_utf8(hnd.type);
                            std::string name_utf8 = to_utf8(hnd.name);
                            if (handle_filter[0] != '\0' &&
                                !case_insensitive_strstr(type_utf8, handle_filter) &&
                                !case_insensitive_strstr(name_utf8, handle_filter)) {
                                continue;
                            }
                            ImGui::TableNextRow();
                            ImGui::TableSetColumnIndex(0);
                            ImGui::Text("0x%llX", hnd.value);
                            ImGui::TableSetColumnIndex(1);
                            ImGui::TextUnformatted(type_utf8.c_str());
                            ImGui::TableSetColumnIndex(2);
                            ImGui::TextUnformatted(name_utf8.c_str());
                        }
                        ImGui::EndTable();
                    }
                    ImGui::EndTabItem();
                }
                ImGui::EndTabBar();
            }
        }
        ImGui::EndChild();
    } else if (current_tab == 1) {
        if (active_pid == 0) {
            ImGui::TextColored(ImVec4(0.961f, 0.961f, 0.969f, 0.500f), "Please select an active process from the Process List first.");
        } else {
            if (scan_running) {
                if (scan_future.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                    unsigned char* res = scan_future.get();
                    scan_running = false;
                    if (res != nullptr) {
                        std::stringstream ss;
                        ss << "Found: 0x" << std::hex << std::uppercase << reinterpret_cast<uintptr_t>(res);
                        mem_scan_status = ss.str();
                        mem_scan_success = true;
                    } else {
                        mem_scan_status = "Pattern not found";
                        mem_scan_success = false;
                    }
                }
            }

            if (active_pid != last_memory_pid) {
                cached_regions = get_committed_memory_regions(active_pid);
                last_memory_pid = active_pid;
            }

            if (ImGui::Button("Refresh Memory Regions")) {
                cached_regions = get_committed_memory_regions(active_pid);
            }
            ImGui::SameLine();
            bool pushed_all = false;
            if (memory_type_filter == 0) {
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.000f, 0.470f, 0.831f, 0.600f));
                pushed_all = true;
            }
            if (ImGui::Button("All")) {
                memory_type_filter = 0;
            }
            if (pushed_all) {
                ImGui::PopStyleColor();
            }
            ImGui::SameLine();
            bool pushed_image = false;
            if (memory_type_filter == 1) {
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.000f, 0.470f, 0.831f, 0.600f));
                pushed_image = true;
            }
            if (ImGui::Button("Image")) {
                memory_type_filter = 1;
            }
            if (pushed_image) {
                ImGui::PopStyleColor();
            }
            ImGui::SameLine();
            bool pushed_mapped = false;
            if (memory_type_filter == 2) {
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.000f, 0.470f, 0.831f, 0.600f));
                pushed_mapped = true;
            }
            if (ImGui::Button("Mapped")) {
                memory_type_filter = 2;
            }
            if (pushed_mapped) {
                ImGui::PopStyleColor();
            }
            ImGui::SameLine();
            bool pushed_private = false;
            if (memory_type_filter == 3) {
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.000f, 0.470f, 0.831f, 0.600f));
                pushed_private = true;
            }
            if (ImGui::Button("Private")) {
                memory_type_filter = 3;
            }
            if (pushed_private) {
                ImGui::PopStyleColor();
            }
            ImGui::SameLine();
            if (ImGui::BeginChild("ScannerControls", ImVec2(0, 260), true)) {
                ImGui::Columns(3, "ScannerColumns", false);

                ImGui::Text("Page Protection");
                ImGui::Spacing();
                ImGui::InputText("Address##Protect", mem_protect_address, sizeof(mem_protect_address));
                ImGui::InputText("Size##Protect", mem_protect_size, sizeof(mem_protect_size));
                ImGui::Combo("New Protect", &mem_protect_choice, protection_names, IM_ARRAYSIZE(protection_names));
            if (ImGui::Button("Modify Protection", ImVec2(-1, 0))) {
                    unsigned long long addr_val = parse_hex_value(mem_protect_address);
                    unsigned long long size_val = parse_hex_value(mem_protect_size);
                    if (addr_val == 0 || size_val == 0) {
                        mem_protect_status = "Invalid address/size";
                        mem_protect_success = false;
                    } else {
                        unsigned long old_p = 0;
                        HANDLE proc_handle = OpenProcess(PROCESS_VM_OPERATION, FALSE, active_pid);
                        if (proc_handle != nullptr) {
                            if (modify_page_protection(proc_handle, reinterpret_cast<unsigned char*>(addr_val), static_cast<unsigned long>(size_val), protection_values[mem_protect_choice], &old_p)) {
                                std::stringstream ss;
                                ss << "Success! Old protect: 0x" << std::hex << old_p;
                                mem_protect_status = ss.str();
                                mem_protect_success = true;
                                cached_regions = get_committed_memory_regions(active_pid);
                            } else {
                                mem_protect_status = "Failed to modify page protection";
                                mem_protect_success = false;
                            }
                            CloseHandle(proc_handle);
                        } else {
                            mem_protect_status = "Failed to open process";
                            mem_protect_success = false;
                        }
                    }
                }
                if (!mem_protect_status.empty()) {
                    ImGui::TextColored(mem_protect_success ? ImVec4(0.2f, 0.8f, 0.2f, 1.0f) : ImVec4(0.8f, 0.2f, 0.2f, 1.0f), "%s", mem_protect_status.c_str());
                }

                ImGui::NextColumn();

                ImGui::Text("Write Bytes");
                ImGui::Spacing();
                ImGui::InputText("Address##Write", mem_write_address, sizeof(mem_write_address));
                ImGui::InputText("Bytes (Hex)##Write", mem_write_bytes, sizeof(mem_write_bytes));
                if (ImGui::Button("Write Memory", ImVec2(-1, 0))) {
                    unsigned long long addr_val = parse_hex_value(mem_write_address);
                    std::vector<unsigned char> bytes_to_write = parse_hex_string(mem_write_bytes);
                    if (addr_val == 0) {
                        mem_write_status = "Invalid target address";
                        mem_write_success = false;
                    } else if (bytes_to_write.empty()) {
                        mem_write_status = "Invalid or empty byte sequence";
                        mem_write_success = false;
                    } else {
                        HANDLE proc_handle = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, active_pid);
                        if (proc_handle != nullptr) {
                            if (write_process_bytes(proc_handle, reinterpret_cast<unsigned char*>(addr_val), bytes_to_write)) {
                                mem_write_status = "Success! Wrote bytes successfully";
                                mem_write_success = true;
                            } else {
                                mem_write_status = "Failed to write process memory";
                                mem_write_success = false;
                            }
                            CloseHandle(proc_handle);
                        } else {
                            mem_write_status = "Failed to open process";
                            mem_write_success = false;
                        }
                    }
                }
                if (!mem_write_status.empty()) {
                    ImGui::TextColored(mem_write_success ? ImVec4(0.2f, 0.8f, 0.2f, 1.0f) : ImVec4(0.8f, 0.2f, 0.2f, 1.0f), "%s", mem_write_status.c_str());
                }

                ImGui::NextColumn();

                ImGui::Text("Pattern Scan (AOB)");
                ImGui::Spacing();
                ImGui::InputText("Start Address##Scan", mem_scan_start, sizeof(mem_scan_start));
                ImGui::InputText("Size##Scan", mem_scan_size, sizeof(mem_scan_size));
                ImGui::InputText("Pattern (Hex)##Scan", mem_scan_pattern, sizeof(mem_scan_pattern));
                ImGui::InputText("Mask (x/?)##Scan", mem_scan_mask, sizeof(mem_scan_mask));
                if (scan_running) {
                    ImGui::Button("Scanning...", ImVec2(-1, 0));
                    ImGui::ProgressBar(-1.0f * (float)ImGui::GetTime(), ImVec2(-1, 0), "Scanning...");
                } else {
                    if (ImGui::Button("Scan Pattern", ImVec2(-1, 0))) {
                        unsigned long long start_val = parse_hex_value(mem_scan_start);
                        unsigned long long size_val = parse_hex_value(mem_scan_size);
                        std::vector<unsigned char> pat_bytes = parse_hex_string(mem_scan_pattern);
                        std::string mask_str = mem_scan_mask;
                        if (start_val == 0 || size_val == 0) {
                            mem_scan_status = "Invalid start address/size";
                            mem_scan_success = false;
                        } else if (pat_bytes.empty()) {
                            mem_scan_status = "Invalid pattern";
                            mem_scan_success = false;
                        } else if (mask_str.length() != pat_bytes.size()) {
                            mem_scan_status = "Mask size mismatch";
                            mem_scan_success = false;
                        } else {
                            mem_scan_status = "Scanning...";
                            mem_scan_success = true;
                            scan_running = true;
                            scan_future = std::async(std::launch::async, [=, pid = active_pid]() -> unsigned char* {
                                HANDLE proc_handle = OpenProcess(PROCESS_VM_READ, FALSE, pid);
                                if (proc_handle == nullptr) {
                                    return nullptr;
                                }
                                unsigned char* res = pattern_scan(proc_handle, reinterpret_cast<unsigned char*>(start_val), static_cast<unsigned long>(size_val), pat_bytes, mask_str);
                                CloseHandle(proc_handle);
                                return res;
                            });
                        }
                    }
                }
                if (!scan_running && !mem_scan_status.empty()) {
                    ImGui::TextColored(mem_scan_success ? ImVec4(0.2f, 0.8f, 0.2f, 1.0f) : ImVec4(0.8f, 0.2f, 0.2f, 1.0f), "%s", mem_scan_status.c_str());
                }

                    ImGui::Columns(1);
                ImGui::EndChild();
            }

            ImGui::Spacing();
            unsigned long long total_image = 0;
            unsigned long long total_mapped = 0;
            unsigned long long total_private = 0;
            for (const auto& region : cached_regions) {
                if (region.type == MEM_IMAGE) {
                    total_image += region.size;
                } else if (region.type == MEM_MAPPED) {
                    total_mapped += region.size;
                } else if (region.type == MEM_PRIVATE) {
                    total_private += region.size;
                }
            }
            unsigned long long total_committed = total_image + total_mapped + total_private;
            if (total_committed > 0) {
                ImGui::Text("Memory Distribution:");
                ImGui::SameLine();
                ImGui::TextColored(ImVec4(0.000f, 0.470f, 0.831f, 1.000f), "Image: %s", format_size(total_image).c_str());
                ImGui::SameLine();
                ImGui::TextColored(ImVec4(0.85f, 0.53f, 0.0f, 1.0f), "Mapped: %s", format_size(total_mapped).c_str());
                ImGui::SameLine();
                ImGui::TextColored(ImVec4(0.2f, 0.8f, 0.2f, 1.0f), "Private: %s", format_size(total_private).c_str());

                ImVec2 bar_pos = ImGui::GetCursorScreenPos();
                float bar_width = ImGui::GetContentRegionAvail().x;
                float bar_height = 16.0f;
                ImDrawList* draw_list = ImGui::GetWindowDrawList();

                float pct_image = (float)total_image / total_committed;
                float pct_mapped = (float)total_mapped / total_committed;
                float pct_private = (float)total_private / total_committed;

                float w_image = bar_width * pct_image;
                float w_mapped = bar_width * pct_mapped;
                float w_private = bar_width * pct_private;

                ImGui::Dummy(ImVec2(bar_width, bar_height));

                float cur_x = bar_pos.x;
                if (w_image > 0.0f) {
                    draw_list->AddRectFilled(ImVec2(cur_x, bar_pos.y), ImVec2(cur_x + w_image, bar_pos.y + bar_height), IM_COL32(0, 120, 212, 255));
                    cur_x += w_image;
                }
                if (w_mapped > 0.0f) {
                    draw_list->AddRectFilled(ImVec2(cur_x, bar_pos.y), ImVec2(cur_x + w_mapped, bar_pos.y + bar_height), IM_COL32(216, 135, 0, 255));
                    cur_x += w_mapped;
                }
                if (w_private > 0.0f) {
                    draw_list->AddRectFilled(ImVec2(cur_x, bar_pos.y), ImVec2(cur_x + w_private, bar_pos.y + bar_height), IM_COL32(50, 160, 50, 255));
                }
                ImGui::Spacing();
            }

            if (ImGui::BeginTable("MemoryTable", 4, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersInnerV, ImVec2(0, -1))) {
                ImGui::TableSetupColumn("Base Address", ImGuiTableColumnFlags_WidthFixed, 160.0f);
                ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 120.0f);
                ImGui::TableSetupColumn("Protection", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 120.0f);
                ImGui::TableHeadersRow();

                for (const auto& region : cached_regions) {
                    if (memory_type_filter == 1 && region.type != MEM_IMAGE) {
                        continue;
                    }
                    if (memory_type_filter == 2 && region.type != MEM_MAPPED) {
                        continue;
                    }
                    if (memory_type_filter == 3 && region.type != MEM_PRIVATE) {
                        continue;
                    }
                    bool is_rwx = (region.protect == PAGE_EXECUTE_READWRITE);
                    if (is_rwx) {
                        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
                    }

                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);

                    std::stringstream base_ss;
                    base_ss << "0x" << std::hex << std::uppercase << std::setw(16) << std::setfill('0') << reinterpret_cast<uintptr_t>(region.base_address);
                    std::string base_str = base_ss.str();

                    bool is_selected = false;
                    if (ImGui::Selectable(base_str.c_str(), is_selected, ImGuiSelectableFlags_SpanAllColumns)) {
                        std::stringstream addr_ss;
                        addr_ss << "0x" << std::hex << std::uppercase << reinterpret_cast<uintptr_t>(region.base_address);
                        std::string addr_raw = addr_ss.str();

                        std::stringstream size_ss;
                        size_ss << "0x" << std::hex << std::uppercase << region.size;
                        std::string size_raw = size_ss.str();

                        strcpy_s(mem_protect_address, addr_raw.c_str());
                        strcpy_s(mem_protect_size, size_raw.c_str());

                        strcpy_s(mem_write_address, addr_raw.c_str());

                        strcpy_s(mem_scan_start, addr_raw.c_str());
                        strcpy_s(mem_scan_size, size_raw.c_str());
                    }

                    ImGui::TableSetColumnIndex(1);
                    std::stringstream size_ss;
                    size_ss << "0x" << std::hex << std::uppercase << region.size;
                    ImGui::TextUnformatted(size_ss.str().c_str());

                    ImGui::TableSetColumnIndex(2);
                    std::string protect_str = protect_to_string(region.protect);
                    if (is_rwx) {
                        protect_str += " [RWX]";
                    }
                    ImGui::TextUnformatted(protect_str.c_str());

                    ImGui::TableSetColumnIndex(3);
                    ImGui::TextUnformatted(type_to_string(region.type).c_str());

                    if (is_rwx) {
                        ImGui::PopStyleColor();
                    }
                }
                ImGui::EndTable();
            }
        }
    } else if (current_tab == 2) {
        if (active_pid == 0) {
            ImGui::TextColored(ImVec4(0.961f, 0.961f, 0.969f, 0.500f), "Please select an active process from the Process List first.");
        } else {
            if (active_pid != last_module_pid) {
                cached_modules = get_process_modules(active_pid);
                last_module_pid = active_pid;
                selected_module_idx = -1;
                selected_module_base = nullptr;
            }

            ImGui::Text("Select Module to Dump:");
            ImGui::Spacing();

            if (ImGui::BeginTable("ModuleTable", 3, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersInnerV, ImVec2(0, 180))) {
                ImGui::TableSetupColumn("Base Address", ImGuiTableColumnFlags_WidthFixed, 160.0f);
                ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                ImGui::TableSetupColumn("Module Name", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();

                for (int i = 0; i < (int)cached_modules.size(); ++i) {
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);

                    bool is_selected = (selected_module_idx == i);
                    std::stringstream ss;
                    ss << "0x" << std::hex << std::uppercase << std::setw(16) << std::setfill('0') << reinterpret_cast<uintptr_t>(cached_modules[i].base_address);
                    std::string base_str = ss.str();

                    if (ImGui::Selectable(base_str.c_str(), is_selected, ImGuiSelectableFlags_SpanAllColumns)) {
                        selected_module_idx = i;
                        selected_module_base = cached_modules[i].base_address;

                        std::stringstream addr_ss;
                        addr_ss << "0x" << std::hex << std::uppercase << reinterpret_cast<uintptr_t>(cached_modules[i].base_address);
                        strcpy_s(manual_base_address, addr_ss.str().c_str());

                        CreateDirectoryA("./dumps", nullptr);
                        std::string mod_name = to_utf8(cached_modules[i].name);
                        size_t dot = mod_name.find_last_of('.');
                        std::string base_name = (dot != std::string::npos) ? mod_name.substr(0, dot) : mod_name;
                        std::string ext = (dot != std::string::npos) ? mod_name.substr(dot) : ".dll";

                        char path_buf[512];
                        snprintf(path_buf, sizeof(path_buf), "./dumps/%s_dumped%s", base_name.c_str(), ext.c_str());
                        strcpy_s(dump_path, path_buf);
                    }

                    ImGui::TableSetColumnIndex(1);
                    std::stringstream size_ss;
                    size_ss << "0x" << std::hex << std::uppercase << cached_modules[i].size;
                    ImGui::TextUnformatted(size_ss.str().c_str());

                    ImGui::TableSetColumnIndex(2);
                    ImGui::TextUnformatted(to_utf8(cached_modules[i].name).c_str());
                }
                ImGui::EndTable();
            }

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            ImGui::InputText("Manual Base Address (Hex)", manual_base_address, sizeof(manual_base_address));
            ImGui::InputText("Output Path", dump_path, sizeof(dump_path));
            ImGui::Spacing();

            char dump_btn_label[128];
            if (selected_module_idx != -1) {
                std::string mod_name = to_utf8(cached_modules[selected_module_idx].name);
                std::string lower_name = mod_name;
                std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), [](char c) {
                    return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                });
                if (lower_name.ends_with(".exe")) {
                    strcpy_s(dump_btn_label, "Dump Process Executable");
                } else {
                    snprintf(dump_btn_label, sizeof(dump_btn_label), "Dump %s", mod_name.c_str());
                }
            } else {
                strcpy_s(dump_btn_label, "Dump Process Executable");
            }

            if (ImGui::Button(dump_btn_label, ImVec2(-1, 40))) {
                unsigned char* target_base = selected_module_base;
                if (manual_base_address[0] != '\0') {
                    std::string addr_str = manual_base_address;
                    if (addr_str.starts_with("0x") || addr_str.starts_with("0X")) {
                        addr_str = addr_str.substr(2);
                    }
                    unsigned long long base_val = 0;
                    std::stringstream ss;
                    ss << std::hex << addr_str;
                    ss >> base_val;
                    target_base = reinterpret_cast<unsigned char*>(base_val);
                }

                if (target_base == nullptr) {
                    dump_status = "Error: No module selected or manual address is invalid.";
                    dump_success = false;
                } else {
                    HANDLE proc_handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, active_pid);
                    if (proc_handle != nullptr) {
                        auto dumped_bytes = dump_process_executable(proc_handle, target_base);
                        if (!dumped_bytes.has_value()) {
                            dump_status = "Error: Failed to read or reconstruct PE headers/sections.";
                            dump_success = false;
                        } else {
                            std::string out_path = dump_path;
                            if (out_path.empty()) {
                                out_path = "module_dump.exe";
                            }
                            std::ofstream out_file(out_path, std::ios::binary);
                            if (!out_file.is_open()) {
                                dump_status = "Error: Failed to open output file for writing.";
                                dump_success = false;
                            } else {
                                out_file.write(reinterpret_cast<const char*>(dumped_bytes->data()), dumped_bytes->size());
                                out_file.close();
                                dump_status = "Success: Dumped " + std::to_string(dumped_bytes->size()) + " bytes to " + out_path;
                                dump_success = true;
                            }
                        }
                        CloseHandle(proc_handle);
                    } else {
                        dump_status = "Error: Failed to open process for dumping.";
                        dump_success = false;
                    }
                }
            }

            ImGui::Spacing();
            if (!dump_status.empty()) {
                if (dump_success) {
                    ImGui::TextColored(ImVec4(0.2f, 0.8f, 0.2f, 1.0f), "%s", dump_status.c_str());
                } else {
                    ImGui::TextColored(ImVec4(0.8f, 0.2f, 0.2f, 1.0f), "%s", dump_status.c_str());
                }
            }
        }
    }
    ImGui::EndChild();
    if (show_warning_popup) {
        ImGui::OpenPopup("Warning: Critical Process");
    }

    if (ImGui::BeginPopupModal("Warning: Critical Process", &show_warning_popup, ImGuiWindowFlags_AlwaysAutoResize)) {
        std::string warn_msg = "Terminating '" + to_utf8(name_to_terminate) + "' (PID: " + std::to_string(pid_to_terminate) + ") can cause Windows to crash or become unstable. Are you sure you want to proceed?";
        ImGui::TextWrapped("%s", warn_msg.c_str());
        ImGui::Spacing();

        if (ImGui::Button("Terminate anyway", ImVec2(150, 0))) {
            terminate_process(pid_to_terminate);
            active_pid = 0;
            active_process_name = L"None";
            cached_processes.clear();
            show_warning_popup = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(150, 0))) {
            show_warning_popup = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    ImGui::End();
}
