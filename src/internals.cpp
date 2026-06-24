#include "internals.h"
#include <tlhelp32.h>
#include <algorithm>

std::vector<process_info> get_active_processes() {
    std::vector<process_info> processes;
    unique_handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (snapshot.get() == INVALID_HANDLE_VALUE || snapshot.get() == nullptr) {
        return processes;
    }
    PROCESSENTRY32W process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32W);
    if (!Process32FirstW(snapshot.get(), &process_entry)) {
        return processes;
    }
    do {
        process_info info;
        info.id = process_entry.th32ProcessID;
        info.name = process_entry.szExeFile;
        processes.push_back(info);
    } while (Process32NextW(snapshot.get(), &process_entry));
    return processes;
}

std::vector<module_info> get_process_modules(unsigned long process_id) {
    std::vector<module_info> modules;
    unique_handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id));
    if (snapshot.get() == INVALID_HANDLE_VALUE || snapshot.get() == nullptr) {
        return modules;
    }
    MODULEENTRY32W module_entry;
    module_entry.dwSize = sizeof(MODULEENTRY32W);
    if (!Module32FirstW(snapshot.get(), &module_entry)) {
        return modules;
    }
    do {
        module_info info;
        info.name = module_entry.szModule;
        info.path = module_entry.szExePath;
        info.base_address = module_entry.modBaseAddr;
        info.size = module_entry.modBaseSize;
        modules.push_back(info);
    } while (Module32NextW(snapshot.get(), &module_entry));
    return modules;
}

std::vector<memory_region> get_committed_memory_regions(unsigned long process_id) {
    std::vector<memory_region> regions;
    unique_handle process(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, process_id));
    if (process.get() == nullptr) {
        return regions;
    }
    unsigned char* current_address = nullptr;
    MEMORY_BASIC_INFORMATION mbi;
    while (VirtualQueryEx(process.get(), current_address, &mbi, sizeof(mbi)) != 0) {
        if (mbi.State == MEM_COMMIT) {
            memory_region region;
            region.base_address = static_cast<unsigned char*>(mbi.BaseAddress);
            region.size = mbi.RegionSize;
            region.protect = mbi.Protect;
            region.state = mbi.State;
            region.type = mbi.Type;
            regions.push_back(region);
        }
        unsigned char* next_address = static_cast<unsigned char*>(mbi.BaseAddress) + mbi.RegionSize;
        if (next_address <= current_address) {
            break;
        }
        current_address = next_address;
    }
    return regions;
}

std::optional<std::vector<unsigned char>> dump_process_executable(HANDLE process, unsigned char* base_address) {
    if (process == nullptr || process == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }
    IMAGE_DOS_HEADER dos_header;
    if (!ReadProcessMemory(process, base_address, &dos_header, sizeof(dos_header), nullptr)) {
        return std::nullopt;
    }
    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        return std::nullopt;
    }
    unsigned char* nt_headers_address = base_address + dos_header.e_lfanew;
    DWORD signature = 0;
    if (!ReadProcessMemory(process, nt_headers_address, &signature, sizeof(signature), nullptr)) {
        return std::nullopt;
    }
    if (signature != IMAGE_NT_SIGNATURE) {
        return std::nullopt;
    }
    IMAGE_FILE_HEADER file_header;
    if (!ReadProcessMemory(process, nt_headers_address + sizeof(DWORD), &file_header, sizeof(file_header), nullptr)) {
        return std::nullopt;
    }
    WORD magic = 0;
    if (!ReadProcessMemory(process, nt_headers_address + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), &magic, sizeof(magic), nullptr)) {
        return std::nullopt;
    }
    unsigned long size_of_headers = 0;
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_NT_HEADERS64 nt_headers_64;
        if (!ReadProcessMemory(process, nt_headers_address, &nt_headers_64, sizeof(nt_headers_64), nullptr)) {
            return std::nullopt;
        }
        size_of_headers = nt_headers_64.OptionalHeader.SizeOfHeaders;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_NT_HEADERS32 nt_headers_32;
        if (!ReadProcessMemory(process, nt_headers_address, &nt_headers_32, sizeof(nt_headers_32), nullptr)) {
            return std::nullopt;
        }
        size_of_headers = nt_headers_32.OptionalHeader.SizeOfHeaders;
    } else {
        return std::nullopt;
    }
    if (size_of_headers == 0) {
        return std::nullopt;
    }
    unsigned long section_headers_offset = dos_header.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + file_header.SizeOfOptionalHeader;
    std::vector<IMAGE_SECTION_HEADER> section_headers(file_header.NumberOfSections);
    if (!ReadProcessMemory(process, base_address + section_headers_offset, section_headers.data(), file_header.NumberOfSections * sizeof(IMAGE_SECTION_HEADER), nullptr)) {
        return std::nullopt;
    }
    unsigned long output_file_size = size_of_headers;
    for (const auto& section : section_headers) {
        unsigned long section_end = section.PointerToRawData + section.SizeOfRawData;
        if (section_end > output_file_size) {
            output_file_size = section_end;
        }
    }
    std::vector<unsigned char> output_buffer(output_file_size, 0);
    if (!ReadProcessMemory(process, base_address, output_buffer.data(), size_of_headers, nullptr)) {
        return std::nullopt;
    }
    for (const auto& section : section_headers) {
        if (section.SizeOfRawData > 0 && section.VirtualAddress > 0) {
            std::vector<unsigned char> section_data(section.SizeOfRawData, 0);
            unsigned long bytes_to_read = (section.Misc.VirtualSize < section.SizeOfRawData && section.Misc.VirtualSize > 0) ? section.Misc.VirtualSize : section.SizeOfRawData;
            ReadProcessMemory(process, base_address + section.VirtualAddress, section_data.data(), bytes_to_read, nullptr);
            if (section.PointerToRawData + section.SizeOfRawData <= output_file_size) {
                std::copy(section_data.begin(), section_data.end(), output_buffer.begin() + section.PointerToRawData);
            }
        }
    }
    return output_buffer;
}

bool enable_debug_privilege() {
    HANDLE token_handle = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle)) {
        return false;
    }
    unique_handle token(token_handle);
    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
        return false;
    }
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(token.get(), FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
        return false;
    }
    return GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

bool terminate_process(unsigned long process_id) {
    unique_handle process(OpenProcess(PROCESS_TERMINATE, FALSE, process_id));
    if (process.get() == nullptr) {
        return false;
    }
    return TerminateProcess(process.get(), 0) != 0;
}

bool modify_page_protection(HANDLE process, unsigned char* base_address, unsigned long size, unsigned long new_protect, unsigned long* old_protect) {
    if (process == nullptr || process == INVALID_HANDLE_VALUE) {
        return false;
    }
    return VirtualProtectEx(process, base_address, size, new_protect, old_protect) != 0;
}

bool write_process_bytes(HANDLE process, unsigned char* address, const std::vector<unsigned char>& bytes) {
    if (process == nullptr || process == INVALID_HANDLE_VALUE) {
        return false;
    }
    SIZE_T bytes_written = 0;
    return WriteProcessMemory(process, address, bytes.data(), bytes.size(), &bytes_written) != 0;
}

unsigned char* pattern_scan(HANDLE process, unsigned char* start_address, unsigned long size, const std::vector<unsigned char>& pattern, const std::string& mask) {
    if (process == nullptr || process == INVALID_HANDLE_VALUE) {
        return nullptr;
    }
    std::vector<unsigned char> buffer(size);
    SIZE_T bytes_read = 0;
    if (!ReadProcessMemory(process, start_address, buffer.data(), size, &bytes_read)) {
        return nullptr;
    }
    if (bytes_read < pattern.size()) {
        return nullptr;
    }
    for (size_t i = 0; i <= bytes_read - pattern.size(); ++i) {
        bool found = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (mask[j] != '?' && pattern[j] != buffer[i + j]) {
                found = false;
                break;
            }
        }
        if (found) {
            return start_address + i;
        }
    }
    return nullptr;
}

struct UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
};

struct PUBLIC_OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG Reserved[22];
};

struct PROCESS_HANDLE_TABLE_ENTRY_INFO {
    HANDLE HandleValue;
    ULONG_PTR HandleCount;
    ULONG_PTR PointerCount;
    ULONG GrantedAccess;
    ULONG ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
};

struct PROCESS_HANDLE_SNAPSHOT_INFORMATION {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
};

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* pfnNtQueryObject)(
    HANDLE Handle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);

std::vector<thread_info> get_process_threads(unsigned long process_id) {
    std::vector<thread_info> threads;
    unique_handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (snapshot.get() == INVALID_HANDLE_VALUE || snapshot.get() == nullptr) {
        return threads;
    }
    THREADENTRY32 thread_entry;
    thread_entry.dwSize = sizeof(THREADENTRY32);
    if (!Thread32First(snapshot.get(), &thread_entry)) {
        return threads;
    }
    do {
        if (thread_entry.th32OwnerProcessID == process_id) {
            thread_info info;
            info.id = thread_entry.th32ThreadID;
            info.priority = thread_entry.tpBasePri;
            threads.push_back(info);
        }
    } while (Thread32Next(snapshot.get(), &thread_entry));
    return threads;
}

std::vector<handle_info> get_process_handles(unsigned long process_id) {
    std::vector<handle_info> result;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        return result;
    }
    pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        return result;
    }
    pfnNtQueryObject NtQueryObject = (pfnNtQueryObject)GetProcAddress(ntdll, "NtQueryObject");
    if (!NtQueryObject) {
        return result;
    }
    unique_handle process(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, FALSE, process_id));
    if (process.get() == nullptr) {
        return result;
    }
    ULONG size = 1024 * 1024;
    std::vector<unsigned char> buffer(size);
    ULONG return_len = 0;
    NTSTATUS status = NtQueryInformationProcess(process.get(), 51, buffer.data(), size, &return_len);
    while (status == 0xC0000004) {
        size *= 2;
        buffer.resize(size);
        status = NtQueryInformationProcess(process.get(), 51, buffer.data(), size, &return_len);
    }
    if (status < 0) {
        return result;
    }
    auto handle_info_list = reinterpret_cast<PROCESS_HANDLE_SNAPSHOT_INFORMATION*>(buffer.data());
    for (ULONG_PTR i = 0; i < handle_info_list->NumberOfHandles; ++i) {
        const auto& handle_entry = handle_info_list->Handles[i];
        HANDLE dup_handle = nullptr;
        if (DuplicateHandle(process.get(), handle_entry.HandleValue, GetCurrentProcess(), &dup_handle, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            handle_info item;
            item.value = reinterpret_cast<unsigned long long>(handle_entry.HandleValue);
            ULONG type_len = 0;
            NtQueryObject(dup_handle, 2, nullptr, 0, &type_len);
            if (type_len > 0) {
                std::vector<unsigned char> type_buf(type_len);
                if (NtQueryObject(dup_handle, 2, type_buf.data(), type_len, &type_len) >= 0) {
                    auto type_info = reinterpret_cast<PUBLIC_OBJECT_TYPE_INFORMATION*>(type_buf.data());
                    if (type_info->TypeName.Buffer && type_info->TypeName.Length > 0) {
                        item.type = std::wstring(type_info->TypeName.Buffer, type_info->TypeName.Length / sizeof(wchar_t));
                    }
                }
            }
            if (!item.type.empty() && item.type != L"File") {
                ULONG name_len = 0;
                NtQueryObject(dup_handle, 1, nullptr, 0, &name_len);
                if (name_len > 0) {
                    std::vector<unsigned char> name_buf(name_len);
                    if (NtQueryObject(dup_handle, 1, name_buf.data(), name_len, &name_len) >= 0) {
                        auto name_info = reinterpret_cast<UNICODE_STRING*>(name_buf.data());
                        if (name_info->Buffer && name_info->Length > 0) {
                            item.name = std::wstring(name_info->Buffer, name_info->Length / sizeof(wchar_t));
                        }
                    }
                }
            }
            CloseHandle(dup_handle);
            result.push_back(item);
        }
    }
    return result;
}

