-- T9 / Black Ops Cold War native director hub
-- Build260: informed by readable LuaJIT decode from earlier logs.

local M = {
    name = "director_hub",
    applied = false,
    lastError = nil,
    wrappedBuilder = nil
}

local function bridge()
    return rawget(_G, "T9CLIENT_BRIDGE")
end

local function log(text)
    pcall(function()
        local b = bridge()
        if b and type(b.log) == "function" then
            b.log("[director_hub] " .. tostring(text))
        end
    end)
end

local function route(network, mode)
    local b = bridge()
    if not b or type(b.route) ~= "function" then
        M.lastError = "T9CLIENT_BRIDGE.route unavailable"
        log(M.lastError)
        return false
    end

    local ok, result = pcall(b.route, network, mode)
    if not ok then
        M.lastError = tostring(result)
        log("route failed: " .. M.lastError)
        return false
    end

    return result ~= false
end

local function dumpKnownLuaUtils()
    pcall(function()
        if not LuaUtils then return end
        local names = {
            "GetDirectorMainMenu",
            "GetOnlineSelectMenu",
            "GetLanSelectMenu",
            "GetLanMenu",
            "ShouldShowCampaign",
            "ShouldShowMultiplayer",
            "ShouldShowZombies",
            "ShouldShowWarzone"
        }

        for _, n in ipairs(names) do
            if type(rawget(LuaUtils, n)) == "function" then
                log("LuaUtils." .. n .. " is present")
            end
        end
    end)
end

local function hideCampaign(menu)
    if not menu then return end

    local names = {
        "Campaign",
        "CampaignButton",
        "campaignButton",
        "CampaignBtn",
        "campaign"
    }

    for _, name in ipairs(names) do
        local button = rawget(menu, name)
        if button then
            pcall(function()
                if type(button.setAlpha) == "function" then button:setAlpha(0) end
                if type(button.makeNotFocusable) == "function" then button:makeNotFocusable() end
                if type(button.setMouseDisabled) == "function" then button:setMouseDisabled(true) end
            end)
        end
    end
end

local function addButton(menu, label, callback)
    if menu and type(menu.AddButton) == "function" then
        local ok, button = pcall(function()
            return menu:AddButton(label, callback)
        end)
        if ok and button then return button end
    end

    if CoD and CoD.ButtonPrompt and type(CoD.ButtonPrompt.new) == "function" then
        local ok, button = pcall(function()
            local b = CoD.ButtonPrompt.new("primary", label, menu, callback)
            if menu and type(menu.addElement) == "function" then
                menu:addElement(b)
            end
            return b
        end)
        if ok and button then return button end
    end

    return nil
end

local function patchMenu(menu)
    if not menu then return menu end
    if rawget(menu, "__t9clientDirectorHub") then return menu end

    rawset(menu, "__t9clientDirectorHub", true)
    hideCampaign(menu)

    -- First custom frontend proof button for the Lua/LUI route.
    -- Once source execution is connected this is a real MenuBuilder child,
    -- not an external renderer overlay.
    local revamped = addButton(menu, "COD REVAMPED", function()
        local b = bridge()
        if b and type(b.log) == "function" then
            b.log("[director_hub] COD REVAMPED custom button clicked")
        end
    end)
    rawset(menu, "__codRevampedCustomButton", revamped)

    local lanMP = addButton(menu, "LAN MULTIPLAYER", function()
        route("lan", "mp")
    end)

    local lanZM = addButton(menu, "LAN ZOMBIES", function()
        route("lan", "zm")
    end)

    rawset(menu, "__t9clientLanMP", lanMP)
    rawset(menu, "__t9clientLanZM", lanZM)

    pcall(function()
        if type(menu.RefreshContent) == "function" then menu:RefreshContent() end
        if type(menu.updateLayout) == "function" then menu:updateLayout() end
        if type(menu.UpdateLayout) == "function" then menu:UpdateLayout() end
    end)

    log("native director menu patched")
    return menu
end

local function builderTable()
    if MenuBuilder and type(MenuBuilder.m_types) == "table" then
        return MenuBuilder.m_types
    end
end

-- Confirmed in readable route bytecode constants.
local preferredBuilders = {
    "FrontendMain",
    "BootMenu",
    "MultiplayerMain",
    "ZombiesMain"
}

local function wrapBuilder(types, name)
    local original = rawget(types, name)
    local marker = name .. "__t9clientDirectorHub"

    if type(original) ~= "function" or rawget(types, marker) then
        return false
    end

    rawset(types, name, function(...)
        local menu = original(...)
        local ok, result = pcall(patchMenu, menu)
        if ok and result then return result end
        return menu
    end)

    rawset(types, marker, true)
    M.wrappedBuilder = name
    M.applied = true
    log("wrapped MenuBuilder.m_types." .. name)
    return true
end

local function looksLikeDirectorBuilder(name)
    if type(name) ~= "string" then return false end
    local n = string.lower(name)

    return string.find(n, "director", 1, true) or
           string.find(n, "frontend", 1, true) or
           string.find(n, "modeselect", 1, true) or
           string.find(n, "online_select", 1, true) or
           string.find(n, "onlineselect", 1, true)
end

function M.apply()
    if M.applied then return true end

    dumpKnownLuaUtils()

    local types = builderTable()
    if not types then
        return false
    end

    for _, name in ipairs(preferredBuilders) do
        if wrapBuilder(types, name) then
            return true
        end
    end

    for name, fn in pairs(types) do
        if type(fn) == "function" and looksLikeDirectorBuilder(name) then
            log("candidate live builder: " .. tostring(name))
            if wrapBuilder(types, name) then
                return true
            end
        end
    end

    return false
end

return M
