// CodRevamped IW8Tools native command dispatcher.
// Built with the existing four tool translation units into ONE native helper.
// Nothing from the proprietary game or from any external converter is embedded.
#include <iostream>
#include <string>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#endif

int IW8MapPack_Entry(int, char**);
int IW8PackageInspect_Entry(int, char**);
int IW8FastfileLab_Entry(int, char**);
int IW8ReverseLab_Entry(int, char**);
#ifdef _WIN32
int MWAssetLab_Entry(int, wchar_t**);
#else
int MWAssetLab_Entry(int, char**);
#endif

#ifdef _WIN32
static std::string utf8(const wchar_t* value) {
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string out(static_cast<size_t>(size), '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, out.data(), size, nullptr, nullptr)) return {};
    out.pop_back();
    return out;
}
int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        std::wcerr << L"IW8Tools.Native <map|fastfile|reverse|assets|packages> [command args...]\n";
        return 2;
    }
    const std::wstring mode(argv[1]);
    if (mode == L"assets") return MWAssetLab_Entry(argc - 1, argv + 1);
    std::vector<std::string> values;
    values.reserve(static_cast<size_t>(argc - 1));
    for (int i = 1; i < argc; ++i) values.push_back(utf8(argv[i]));
    std::vector<char*> pointers;
    pointers.reserve(values.size());
    for (auto& value : values) pointers.push_back(value.data());
    if (mode == L"packages") return IW8PackageInspect_Entry(argc - 1, pointers.data());
    if (mode == L"map") return IW8MapPack_Entry(argc - 1, pointers.data());
    if (mode == L"fastfile") return IW8FastfileLab_Entry(argc - 1, pointers.data());
    if (mode == L"reverse") return IW8ReverseLab_Entry(argc - 1, pointers.data());
    std::wcerr << L"Unknown IW8Tools native command: " << mode << L"\n";
    return 2;
}
#else
int main(int argc, char** argv) {
    if (argc < 2) { std::cerr << "IW8Tools.Native <map|fastfile|reverse|assets|packages> [args]\n"; return 2; }
    const std::string mode(argv[1]);
    if (mode == "packages") return IW8PackageInspect_Entry(argc - 1, argv + 1);
    if (mode == "assets") return MWAssetLab_Entry(argc - 1, argv + 1);
    if (mode == "map") return IW8MapPack_Entry(argc - 1, argv + 1);
    if (mode == "fastfile") return IW8FastfileLab_Entry(argc - 1, argv + 1);
    if (mode == "reverse") return IW8ReverseLab_Entry(argc - 1, argv + 1);
    std::cerr << "Unknown IW8Tools native command: " << mode << '\n';
    return 2;
}
#endif
