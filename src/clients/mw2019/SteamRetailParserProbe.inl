// Opt-in, read-only code inspection for one exact retail build. No debugger,
// protection changes, exception suppression, auth writes, or whole-memory dump.
namespace steam_retail_probe
{
    bool Copy(const void* source, void* destination, size_t size) noexcept
    {
        __try { std::memcpy(destination, source, size); return true; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }

    void Window(FILE* log, const unsigned char* base, size_t imageSize,
        size_t rva, size_t length) noexcept
    {
        unsigned char bytes[1024]{};
        if (length > sizeof(bytes) || rva >= imageSize || length > imageSize-rva ||
            !Copy(base+rva, bytes, length)) return;
        std::fprintf(log, "CODE rva=0x%zX bytes=", rva);
        for (size_t i=0; i<length; ++i) std::fprintf(log, "%02X", bytes[i]);
        std::fprintf(log, "\n");
    }

    DWORD WINAPI Worker(void*) noexcept
    {
        Sleep(60000);
        const auto base = reinterpret_cast<const unsigned char*>(GetModuleHandleW(nullptr));
        IMAGE_DOS_HEADER dos{};
        IMAGE_NT_HEADERS64 nt{};
        if (!Copy(base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
            dos.e_lfanew < 0 || dos.e_lfanew > 0x100000 ||
            !Copy(base+dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE ||
            nt.FileHeader.TimeDateStamp != 0x69DD404Eu ||
            nt.OptionalHeader.SizeOfImage != 0x21679200u ||
            nt.OptionalHeader.AddressOfEntryPoint != 0x06E4931Cu) return 0;
        FILE* log = nullptr;
        if (fopen_s(&log, "steam_retail_parser.log", "w") || !log) return 0;
        std::fprintf(log, "Exact Steam retail code inspection; read-only; base=%p\n", base);
        // Call targets recovered from the first capture, not borrowed from 1.44.
        const size_t parserRvas[] = {0x6CACC30, 0x6CAC5C0, 0x6CAD0F0, 0x6CBAF00, 0x6CBB960};
        const char* parserLabels[] = {"title-parser", "umbrella-parser", "uno-parser", "title-wrapper", "login-parser"};
        for (unsigned p=0; p<5; ++p)
        {
            std::fprintf(log, "XREF field=%s rva=0x%zX\n", parserLabels[p], parserRvas[p]);
            for (unsigned block=0; block<3; ++block)
                Window(log, base, nt.OptionalHeader.SizeOfImage, parserRvas[p]+block*1024, 1024);
        }
        constexpr size_t targets[] = {0x71778B0, 0x70A8BA4, 0x7175990, 0x7176B50};
        const char* labels[] = {"title-data-error", "title", "titleID", "extended-auth-report"};
        const size_t headers = dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader;
        unsigned hits = 0;
        unsigned fieldHits[4]{};
        unsigned skipped = 0;
        for (unsigned s=0; s<nt.FileHeader.NumberOfSections && s<96; ++s)
        {
            IMAGE_SECTION_HEADER section{};
            if (!Copy(base+headers+s*sizeof(section), &section, sizeof(section))) break;
            if (!(section.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
            const size_t begin = section.VirtualAddress;
            const size_t end = begin + section.Misc.VirtualSize;
            if (end > nt.OptionalHeader.SizeOfImage || end < begin) continue;
            for (size_t page=begin; page<end && hits<64; page+=4096)
            {
                unsigned char bytes[4096]{};
                const size_t take = (std::min)(sizeof(bytes), end-page);
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(base+page, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT ||
                    (mbi.Protect & (PAGE_GUARD|PAGE_NOACCESS)) || !Copy(base+page, bytes, take))
                { ++skipped; continue; }
                for (size_t i=0; i<4096 && i+7<=take && hits<64; ++i)
                {
                    if ((bytes[i]!=0x48 && bytes[i]!=0x4C) || bytes[i+1]!=0x8D ||
                        (bytes[i+2]&0xC7)!=0x05) continue;
                    int displacement=0;
                    std::memcpy(&displacement, bytes+i+3, sizeof(displacement));
                    const size_t rva=page+i;
                    const auto target=static_cast<long long>(rva+7)+displacement;
                    for (unsigned t=0; t<4; ++t)
                    {
                        if (target!=static_cast<long long>(targets[t])) continue;
                        if (fieldHits[t] >= (t == 3 ? 16u : 8u)) continue;
                        ++fieldHits[t];
                        ++hits;
                        std::fprintf(log, "XREF field=%s rva=0x%zX\n", labels[t], rva);
                        Window(log, base, nt.OptionalHeader.SizeOfImage, rva, 384);
                        DWORD64 imageBase=0;
                        const auto function=RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(base+rva), &imageBase, nullptr);
                        if (function && imageBase==reinterpret_cast<DWORD64>(base))
                        {
                            std::fprintf(log, "OWNER begin=0x%lX end=0x%lX\n", function->BeginAddress, function->EndAddress);
                            Window(log, base, nt.OptionalHeader.SizeOfImage, function->BeginAddress,
                                (std::min)(size_t(1024), size_t(function->EndAddress-function->BeginAddress)));
                        }
                    }
                }
            }
        }
        std::fprintf(log, "DONE hits=%u skippedPages=%u stateWrites=off\n", hits, skipped);
        std::fclose(log);
        return 0;
    }
}
