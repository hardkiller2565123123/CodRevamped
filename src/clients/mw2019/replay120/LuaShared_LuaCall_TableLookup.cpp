// Complete shipped StringTable Lua binding. The local DW storefront publishes
// zero-price offers; its UI reads prices from the native bundle table instead
// of the downloaded SKU catalog, so reflect that policy in the same consumer.
extern "C"
{
    bool DW_LocalBackend_IsEnabled();
    int func_1420838B0(void *);                       // lua_gettop
    bool func_142083A30(void *, int);                 // lua_isstring
    int func_1420839E0(void *, int);                  // lua_isnumber
    const char *func_142084950(void *, int, void *);  // lua_tolstring
    long long func_1419B78C0(void *, int);            // lua_tointeger
    int func_142089FB0(void *, const char *, ...);    // luaL_error
    bool func_1413E33E0(const char *, const void **); // Stringtable_GetAssetNonDefault
    const char *func_1413E2BA0(const void *, int, const char *, int); // StringTable_Lookup
    void func_142084120(void *, const char *);                        // lua_pushstring
    void func_1419CDD30(const char *, const char *, void *);          // native shared-Lua warning
}

extern "C" int func_1419BA320(void *vm)
{
    constexpr const char *usage =
        "USAGE: StringTable.TableLookup(<table>, <search column>, <value>, <return column>)";
    if (func_1420838B0(vm) != 4 || !func_142083A30(vm, 1) || !func_1420839E0(vm, 2) ||
        !func_142083A30(vm, 3) || !func_1420839E0(vm, 4))
        return func_142089FB0(vm, usage);
    const char *name = func_142084950(vm, 1, nullptr);
    const int search = int(func_1419B78C0(vm, 2));
    const char *key = func_142084950(vm, 3, nullptr);
    const int column = int(func_1419B78C0(vm, 4));
    const void *table = nullptr;
    const char *value = "";
    if (func_1413E33E0(name, &table))
    {
        value = func_1413E2BA0(table, search, key, column);
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
        func_1419CDD30("StringTable.TableLookup: Table not found", name, vm);
    func_142084120(vm, value);
    if (func_1420838B0(vm) < 1)
        return func_142089FB0(vm, "StringTable.TableLookup return stack mismatch");
    return 1;
}
