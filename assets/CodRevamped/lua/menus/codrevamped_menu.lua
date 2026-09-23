-- CodRevamped network split menu v2
-- Retail Cold War frontend router.
-- This file is also mirrored to mods/lua/director_hub.lua because the existing
-- CodRevamped Lua bridge already owns that loose-module load path.
-- Public COD/Demonware blocking remains owned by the DLL and is never disabled here.

local M = {}

local function crLog(text)
    local msg = "[CodRevamped Menu] " .. tostring(text)
    if Engine ~= nil and Engine.PrintInfo ~= nil then
        pcall(Engine.PrintInfo, 0, msg .. "\n")
    elseif print ~= nil then
        pcall(print, msg)
    end
end

local function controllerIndex()
    if Engine ~= nil and Engine.GetPrimaryController ~= nil then
        local ok, value = pcall(Engine.GetPrimaryController)
        if ok and value ~= nil then return value end
    end
    return 0
end

local function enumValue(tableName, names, fallback)
    if Enum ~= nil and Enum[tableName] ~= nil then
        local bucket = Enum[tableName]
        for _, name in ipairs(names) do
            if bucket[name] ~= nil then return bucket[name] end
        end
    end
    return fallback
end

local MODE_MP = enumValue("LobbyMainMode", {
    "LOBBY_MAINMODE_MP", "MAINMODE_MP", "MP"
}, 1)
local MODE_ZM = enumValue("LobbyMainMode", {
    "LOBBY_MAINMODE_ZM", "MAINMODE_ZM", "ZM", "ZOMBIES"
}, 0)

local function setModelPath(path, value)
    if Engine == nil or Engine.GetGlobalModel == nil or
       Engine.GetModel == nil or Engine.SetModelValue == nil then
        return false
    end
    local okRoot, root = pcall(Engine.GetGlobalModel)
    if not okRoot or root == nil then return false end
    local okModel, model = pcall(Engine.GetModel, root, path)
    if not okModel or model == nil then return false end
    return pcall(Engine.SetModelValue, model, value)
end

local function setMainMode(mode)
    setModelPath("lobbyRoot.mainMode", mode)
    setModelPath("lobbyRoot.lobbyMainMode", mode)
end

local function getSelectTarget(kind, controller)
    if LuaUtils == nil then return nil end
    local fn = kind == "lan" and LuaUtils.GetLanSelectMenu or LuaUtils.GetOnlineSelectMenu
    if fn == nil then return nil end
    local ok, target = pcall(fn, controller)
    if ok and target ~= nil then return target end
    ok, target = pcall(fn)
    if ok then return target end
    return nil
end

local function navigateStock(controller, target)
    if target == nil then return false end

    if Lobby ~= nil and Lobby.ProcessNavigate ~= nil then
        local ok = pcall(Lobby.ProcessNavigate, controller, target)
        if ok then return true end
        ok = pcall(Lobby.ProcessNavigate, target, controller)
        if ok then return true end
        ok = pcall(Lobby.ProcessNavigate, target)
        if ok then return true end
    end

    if CoD ~= nil and CoD.LobbyBase ~= nil and CoD.LobbyBase.ProcessNavigate ~= nil then
        local ok = pcall(CoD.LobbyBase.ProcessNavigate, controller, target)
        if ok then return true end
        ok = pcall(CoD.LobbyBase.ProcessNavigate, target, controller)
        if ok then return true end
    end

    return false
end

local function route(controller, kind, mode, label)
    setMainMode(mode)
    local target = getSelectTarget(kind, controller)
    if navigateStock(controller, target) then
        crLog(label .. " -> stock " .. kind .. " select menu")
        return true
    end
    crLog(label .. " blocked: stock select target/navigation helper unavailable")
    return false
end

function M.onlineMP(controller)
    return route(controller, "online", MODE_MP, "Online Multiplayer")
end

function M.onlineZM(controller)
    return route(controller, "online", MODE_ZM, "Online Zombies")
end

function M.lanMP(controller)
    return route(controller, "lan", MODE_MP, "LAN Multiplayer")
end

function M.lanZM(controller)
    return route(controller, "lan", MODE_ZM, "LAN Zombies")
end

local function setTextSafe(element, text)
    if element ~= nil and element.setText ~= nil then
        pcall(element.setText, element, text)
    end
end

local function makeButton(controller, label, action, y)
    if LUI == nil or LUI.UIElement == nil or LUI.UIElement.new == nil then
        return nil
    end

    local button = LUI.UIElement.new()
    button.id = "CodRevamped_" .. string.gsub(label, " ", "_")
    button.m_focusable = true
    if button.setLeftRight ~= nil then button:setLeftRight(true, false, 80, 620) end
    if button.setTopBottom ~= nil then button:setTopBottom(true, false, y, y + 48) end

    if LUI.UIText ~= nil and LUI.UIText.new ~= nil then
        local text = LUI.UIText.new()
        if text.setLeftRight ~= nil then text:setLeftRight(true, true, 18, -18) end
        if text.setTopBottom ~= nil then text:setTopBottom(true, true, 0, 0) end
        setTextSafe(text, label)
        if button.addElement ~= nil then button:addElement(text) end
    end

    if button.registerEventHandler ~= nil then
        button:registerEventHandler("button_action", function(element, event)
            local c = controller
            if event ~= nil and event.controller ~= nil then c = event.controller end
            action(c)
            return true
        end)
        button:registerEventHandler("leftmouseup", function(element, event)
            local c = controller
            if event ~= nil and event.controller ~= nil then c = event.controller end
            action(c)
            return true
        end)
    end
    return button
end

function M.register()
    if LUI == nil or LUI.createMenu == nil or CoD == nil or
       CoD.Menu == nil or CoD.Menu.NewForUIEditor == nil then
        crLog("register blocked: LUI/CoD menu globals not ready")
        return false
    end

    LUI.createMenu.CodRevampedNetworkSelect = function(controller)
        local menu = CoD.Menu.NewForUIEditor("CodRevampedNetworkSelect")
        if menu == nil then return nil end
        menu.id = "CodRevampedNetworkSelect"
        menu.soundSet = "default"
        menu.anyChildUsesUpdateState = true
        if menu.setOwner ~= nil then menu:setOwner(controller) end

        if LUI.UIText ~= nil and LUI.UIText.new ~= nil then
            local title = LUI.UIText.new()
            if title.setLeftRight ~= nil then title:setLeftRight(true, false, 80, 720) end
            if title.setTopBottom ~= nil then title:setTopBottom(true, false, 100, 150) end
            setTextSafe(title, "COD REVAMPED - NETWORK")
            if menu.addElement ~= nil then menu:addElement(title) end
        end

        local buttons = {
            makeButton(controller, "ONLINE MULTIPLAYER", M.onlineMP, 190),
            makeButton(controller, "ONLINE ZOMBIES", M.onlineZM, 246),
            makeButton(controller, "LAN MULTIPLAYER", M.lanMP, 322),
            makeButton(controller, "LAN ZOMBIES", M.lanZM, 378)
        }

        local first = nil
        for _, button in ipairs(buttons) do
            if button ~= nil then
                if first == nil then first = button end
                if menu.addElement ~= nil then menu:addElement(button) end
            end
        end

        if first ~= nil and first.processEvent ~= nil then
            pcall(first.processEvent, first, { name = "gain_focus", controller = controller })
        end

        crLog("CodRevampedNetworkSelect opened")
        return menu
    end

    LUI.createMenu.CodRevamped = LUI.createMenu.CodRevampedNetworkSelect
    crLog("registered CodRevampedNetworkSelect")
    return true
end

function M.open(controller)
    controller = controller or controllerIndex()
    local name = "CodRevampedNetworkSelect"

    -- The shipped frontend dump contains CoD.OpenMenu. Use it first, but keep
    -- all variants guarded because T9 builds differ in argument order.
    if CoD ~= nil and CoD.OpenMenu ~= nil then
        local ok = pcall(CoD.OpenMenu, name, controller)
        if ok then crLog("open via CoD.OpenMenu(name, controller)"); return true end
        ok = pcall(CoD.OpenMenu, controller, name)
        if ok then crLog("open via CoD.OpenMenu(controller, name)"); return true end
    end

    -- Common LUI flow-manager route. It is attempted only when the object is
    -- already present in this build and is fully protected by pcall.
    if LUI ~= nil and LUI.FlowManager ~= nil and LUI.FlowManager.RequestAddMenu ~= nil then
        local ok = pcall(LUI.FlowManager.RequestAddMenu, nil, name, true, controller, false)
        if ok then crLog("open via LUI.FlowManager.RequestAddMenu"); return true end
        ok = pcall(LUI.FlowManager.RequestAddMenu, name, true, controller)
        if ok then crLog("open via LUI.FlowManager.RequestAddMenu compact"); return true end
    end

    if Engine ~= nil and Engine.OpenMenu ~= nil then
        local ok = pcall(Engine.OpenMenu, controller, name)
        if ok then crLog("open via Engine.OpenMenu"); return true end
    end

    crLog("open blocked: no live Lua menu opener accepted the request")
    return false
end

-- Loading the DirectorHub bridge is now enough for the test: register and open
-- immediately. This avoids the unvalidated native LUI_OpenMenu resolver.
local registered = M.register()
if registered then
    M.open(controllerIndex())
end

_G.CodRevampedNetworkMenu = M
return M
