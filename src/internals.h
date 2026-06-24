#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <vector>
#include <string>
#include <optional>
#include <memory>

struct handle_deleter {
    using pointer = HANDLE;
    void operator()(HANDLE handle) const noexcept {
        if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    }
};

using unique_handle = std::unique_ptr<void, handle_deleter>;

struct process_info {
    unsigned long id;
    std::wstring name;
};

struct module_info {
    std::wstring name;
    std::wstring path;
    unsigned char* base_address;
    unsigned long size;
};

struct memory_region {
    unsigned char* base_address;
    unsigned long long size;
    unsigned long protect;
    unsigned long state;
    unsigned long type;
};

struct thread_info {
    unsigned long id;
    long priority;
};

struct handle_info {
    unsigned long long value;
    std::wstring type;
    std::wstring name;
};

std::vector<process_info> get_active_processes();

std::vector<module_info> get_process_modules(unsigned long process_id);

std::vector<memory_region> get_committed_memory_regions(unsigned long process_id);

std::vector<thread_info> get_process_threads(unsigned long process_id);

std::vector<handle_info> get_process_handles(unsigned long process_id);

std::optional<std::vector<unsigned char>> dump_process_executable(HANDLE process, unsigned char* base_address);

bool enable_debug_privilege();

bool terminate_process(unsigned long process_id);

bool modify_page_protection(HANDLE process, unsigned char* base_address, unsigned long size, unsigned long new_protect, unsigned long* old_protect);

bool write_process_bytes(HANDLE process, unsigned char* address, const std::vector<unsigned char>& bytes);

unsigned char* pattern_scan(HANDLE process, unsigned char* start_address, unsigned long size, const std::vector<unsigned char>& pattern, const std::string& mask);

