-- CodRevamped stock LAN cards v5
-- Stock datasource extension descriptor.  Not executed through DirectorHub.
-- Keeps the original root cards and appends LAN Multiplayer / LAN Zombies.

local M = {}

local function mainMode(name, fallback)
    if Enum ~= nil and Enum.LobbyMainMode ~= nil then
        local e = Enum.LobbyMainMode
        if name == "MP" then
            return e.LOBBY_MAINMODE_MP or e.MAINMODE_MP or e.MP or fallback
        end
        return e.LOBBY_MAINMODE_ZM or e.MAINMODE_ZM or e.ZM or e.ZOMBIES or fallback
    end
    return fallback
end

local MP = mainMode("MP", 1)
local ZM = mainMode("ZM", 0)

local function setMainMode(mode)
    if Engine == nil or Engine.GetGlobalModel == nil or Engine.GetModel == nil or Engine.SetModelValue == nil then
        return
    end
    local okRoot, root = pcall(Engine.GetGlobalModel)
    if not okRoot or root == nil then return end
    local okModel, model = pcall(Engine.GetModel, root, "lobbyRoot.mainMode")
    if okModel and model ~= nil then pcall(Engine.SetModelValue, model, mode) end
end

local function navigateLan(controller, mode)
    setMainMode(mode)
    if LuaUtils == nil or LuaUtils.GetLanSelectMenu == nil then return false end
    local okTarget, target = pcall(LuaUtils.GetLanSelectMenu, controller or 0)
    if not okTarget or target == nil then
        okTarget, target = pcall(LuaUtils.GetLanSelectMenu)
    end
    if not okTarget or target == nil then return false end

    if Lobby ~= nil and Lobby.ProcessNavigate ~= nil then
        if pcall(Lobby.ProcessNavigate, controller or 0, target) then return true end
        if pcall(Lobby.ProcessNavigate, target, controller or 0) then return true end
        if pcall(Lobby.ProcessNavigate, target) then return true end
    end
    if CoD ~= nil and CoD.LobbyBase ~= nil and CoD.LobbyBase.ProcessNavigate ~= nil then
        if pcall(CoD.LobbyBase.ProcessNavigate, controller or 0, target) then return true end
        if pcall(CoD.LobbyBase.ProcessNavigate, target, controller or 0) then return true end
    end
    return false
end

local function card(id, label, mode)
    return {
        models = {
            name = id,
            displayName = label,
            mainMode = mode,
            available = true,
            hidden = false
        },
        properties = {
            actionParam = id,
            action = function(self, element, controller)
                return navigateLan(controller or 0, mode)
            end
        }
    }
end

M.cards = {
    card("codrevamped_lan_mp", "LAN MULTIPLAYER", MP),
    card("codrevamped_lan_zm", "LAN ZOMBIES", ZM)
}

function M.AppendTo(cards)
    if type(cards) ~= "table" then return cards end
    for _, value in ipairs(M.cards) do
        table.insert(cards, value)
    end
    return cards
end

return M
