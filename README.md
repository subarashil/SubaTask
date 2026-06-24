A simple process manager and memory manipulation tool written in C++ using Dear ImGui and DirectX 11.

Features
List active processes with a search filter and terminate task option.
View detailed process info, including active threads and handles.
Memory scanner to modify page protections, write bytes, and perform pattern scans (AOB).
PE Dumper to list loaded modules and reconstruct/dump executables from memory.
How to compile
To compile on Windows using MSVC, open your terminal in the project folder and run:

cmd


build.bat
This will compile the source files using Visual Studio build tools and output the taskmgr_port.exe executable.

Requirements:

Visual Studio installed (with C++20 support).
