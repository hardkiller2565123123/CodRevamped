// The CSV row reader is a separate native Lua entry point from keyed lookup.
extern "C"
{
    bool DW_LocalBackend_IsEnabled();
    int func_1420838B0(void *);
    bool func_142083A30(void *, int);
    int func_1420839E0(void *, int);
    const char *func_142084950(void *, int, void *);
    long long func_1419B78C0(void *, int);
    int func_142089FB0(void *, const char *, ...);
    bool func_1413E33E0(const char *, const void **);
    const char *func_1413E2B40(const void *, int, int);
    void func_142084120(void *, const char *);
    void func_1419CDD30(const char *, const char *, void *);
}

extern "C" int func_1419BA610(void *vm)
{
    constexpr const char *usage = "USAGE: StringTable.TableLookupByRow(<table>, <row>, <column>)";
    if (func_1420838B0(vm) != 3 || !func_142083A30(vm, 1) || !func_1420839E0(vm, 2) ||
        !func_1420839E0(vm, 3))
        return func_142089FB0(vm, usage);
    const char *name = func_142084950(vm, 1, nullptr);
    const int row = int(func_1419B78C0(vm, 2)), column = int(func_1419B78C0(vm, 3));
    const void *table = nullptr;
    const char *value = "";
    if (func_1413E33E0(name, &table))
    {
        value = func_1413E2B40(table, row, column);
        if (value && *value && DW_LocalBackend_IsEnabled())
        {
            const auto equals = [name](const char *expected)
            {
                unsigned i = 0;
                while (name[i] && name[i] == expected[i])
                    ++i;
                return !name[i] && !expected[i];
            };
            if ((equals("loot/bundle_ids.csv") && (column == 10 || column == 11 || column == 36)) ||
                (equals("loot/battlepass_ids.csv") && (column == 8 || column == 9 || column == 20)))
                value = "0";
        }
    }
    else
        func_1419CDD30("StringTable.TableLookupByRow: Table not found", name, vm);
    func_142084120(vm, value);
    if (func_1420838B0(vm) < 1)
        return func_142089FB0(vm, "StringTable.TableLookupByRow return stack mismatch");
    return 1;
}
