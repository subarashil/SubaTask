call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
cl.exe /EHsc /std:c++20 /DUNICODE /D_UNICODE /Isrc /Iimgui src\internals.cpp src\gui.cpp src\main.cpp imgui\imgui.cpp imgui\imgui_draw.cpp imgui\imgui_tables.cpp imgui\imgui_widgets.cpp imgui\imgui_impl_win32.cpp imgui\imgui_impl_dx11.cpp /Fe:taskmgr_port.exe dwmapi.lib d3d11.lib dxgi.lib user32.lib gdi32.lib advapi32.lib
del *.obj
