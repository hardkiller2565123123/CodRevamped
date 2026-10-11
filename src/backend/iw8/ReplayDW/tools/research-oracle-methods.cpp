// Read type declarations and independently look up emitted function symbols.
// A complete PDB type does not prove that its method bodies were linked.
#include <windows.h>
#include <dia2.h>
#include <cstdio>
#include <string>
#include <set>

static std::wstring symbolName(IDiaSymbol *symbol)
{
    BSTR value = nullptr;
    symbol->get_name(&value);
    const std::wstring result = value ? value : L"";
    SysFreeString(value);
    return result;
}

static void quoted(const std::wstring &value)
{
    std::putchar('"');
    for (const wchar_t character : value)
    {
        if (character == L'"' || character == L'\\')
            std::putchar('\\');
        if (character >= 32 && character < 127)
            std::putchar(static_cast<char>(character));
    }
    std::putchar('"');
}

static void describe(
    IDiaSymbol *global, IDiaSymbol *type, std::set<DWORD> &visited, unsigned depth, unsigned &count)
{
    DWORD identifier = 0;
    type->get_symIndexId(&identifier);
    if (depth > 8 || !visited.insert(identifier).second)
        return;
    const auto parent = symbolName(type);
    IDiaEnumSymbols *methods = nullptr;
    if (type->findChildren(SymTagFunction, nullptr, nsNone, &methods) == S_OK && methods)
    {
        IDiaSymbol *method = nullptr;
        ULONG received = 0;
        while (methods->Next(1, &method, &received) == S_OK && received == 1)
        {
            DWORD declaration = 0;
            method->get_symIndexId(&declaration);
            const auto name = symbolName(method);
            const auto qualified =
                name.find(L"::") == std::wstring::npos ? parent + L"::" + name : name;
            BOOL isVirtual = FALSE, pure = FALSE;
            const HRESULT virtualResult = method->get_virtual(&isVirtual);
            const HRESULT pureResult =
                virtualResult == S_OK && isVirtual ? method->get_pure(&pure) : S_FALSE;
            if (count++)
                std::putchar(',');
            std::printf("{\"owner_type\":");
            quoted(parent);
            std::printf(",\"method\":");
            quoted(qualified);
            std::printf(",\"declaration_symbol_id\":%lu", declaration);
            // DIA's virtualBaseOffset describes virtual inheritance, not a
            // method's vtable slot. Do not emit it as method-layout evidence.
            // Pure applies only to a virtual method, and unavailable properties
            // must remain unknown rather than being reported as false.
            std::printf(",\"virtual\":%s,\"pure\":%s,\"linked_name_candidates\":[",
                        virtualResult == S_OK ? (isVirtual ? "true" : "false") : "null",
                        pureResult == S_OK ? (pure ? "true" : "false") : "null");
            IDiaEnumSymbols *functions = nullptr;
            unsigned matched = 0;
            if (global->findChildren(
                    SymTagFunction, qualified.c_str(), nsCaseSensitive, &functions) == S_OK &&
                functions)
            {
                IDiaSymbol *function = nullptr;
                ULONG got = 0;
                while (functions->Next(1, &function, &got) == S_OK && got == 1)
                {
                    DWORD rva = 0;
                    ULONGLONG size = 0;
                    function->get_relativeVirtualAddress(&rva);
                    function->get_length(&size);
                    if (rva && size)
                    {
                        if (matched++)
                            std::putchar(',');
                        std::printf("{\"oracle_rva\":%lu,\"size\":%llu}", rva, size);
                    }
                    function->Release();
                }
                functions->Release();
            }
            std::printf("]}");
            method->Release();
        }
        methods->Release();
    }
    IDiaEnumSymbols *bases = nullptr;
    if (type->findChildren(SymTagBaseClass, nullptr, nsNone, &bases) == S_OK && bases)
    {
        IDiaSymbol *base = nullptr;
        ULONG received = 0;
        while (bases->Next(1, &base, &received) == S_OK && received == 1)
        {
            IDiaSymbol *baseType = nullptr;
            if (base->get_type(&baseType) == S_OK && baseType)
            {
                describe(global, baseType, visited, depth + 1, count);
                baseType->Release();
            }
            base->Release();
        }
        bases->Release();
    }
}

int wmain(int argc, wchar_t **argv)
{
    if (argc != 3)
        return 2;
    const auto library = LoadLibraryW(L"C:\\Program Files\\Microsoft Visual "
                                      L"Studio\\18\\Community\\DIA SDK\\bin\\amd64\\msdia140.dll");
    if (!library)
        return 3;
    const auto create = reinterpret_cast<HRESULT(STDAPICALLTYPE *)(REFCLSID, REFIID, void **)>(
        GetProcAddress(library, "DllGetClassObject"));
    IClassFactory *factory = nullptr;
    IDiaDataSource *source = nullptr;
    IDiaSession *session = nullptr;
    IDiaSymbol *global = nullptr;
    HRESULT result =
        create ? create(__uuidof(DiaSource), IID_IClassFactory, reinterpret_cast<void **>(&factory))
               : E_FAIL;
    if (SUCCEEDED(result))
        result = factory->CreateInstance(
            nullptr, __uuidof(IDiaDataSource), reinterpret_cast<void **>(&source));
    if (SUCCEEDED(result))
        result = source->loadDataFromPdb(argv[1]);
    if (SUCCEEDED(result))
        result = source->openSession(&session);
    if (SUCCEEDED(result))
        result = session->get_globalScope(&global);
    const auto cleanup = [&]()
    {
        if (global)
            global->Release();
        if (session)
            session->Release();
        if (source)
            source->Release();
        if (factory)
            factory->Release();
        FreeLibrary(library);
    };
    if (FAILED(result))
    {
        std::fprintf(stderr,
                     "Cannot open oracle PDB: HRESULT 0x%08lx\n",
                     static_cast<unsigned long>(result));
        cleanup();
        return 4;
    }
    GUID guid{};
    DWORD age = 0;
    global->get_guid(&guid);
    global->get_age(&age);
    wchar_t identity[64]{};
    StringFromGUID2(guid, identity, 64);
    std::printf(
        "{\"schema\":1,\"scope\":\"Oracle method declarations and emitted qualified-name "
        "candidates; overload binding and target-build identity are not established\",\"guid\":");
    quoted(identity);
    std::printf(",\"age\":%lu,\"requested_type\":", age);
    quoted(argv[2]);
    std::printf(",\"methods\":[");
    IDiaEnumSymbols *types = nullptr;
    unsigned count = 0, matchedTypes = 0;
    if (global->findChildren(SymTagUDT, argv[2], nsCaseSensitive, &types) == S_OK && types)
    {
        IDiaSymbol *type = nullptr;
        ULONG received = 0;
        std::set<DWORD> visited;
        while (types->Next(1, &type, &received) == S_OK && received == 1)
        {
            ++matchedTypes;
            describe(global, type, visited, 0, count);
            type->Release();
        }
        types->Release();
    }
    std::printf("],\"type_match_count\":%u}\n", matchedTypes);
    cleanup();
    return matchedTypes ? 0 : 5;
}
