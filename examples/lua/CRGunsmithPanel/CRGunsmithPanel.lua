-- Example editable CodRevamped LUI source. Export from IW8Tools for changes.
-- Requires the experimental, exact-build LuaFile bridge to be enabled and validated.
LUI = LUI or {}
LUI.createMenu = LUI.createMenu or {}
LUI.createMenu["CRGunsmithPanel"] = function(controller)
    local root = LUI.UIElement.new()
    root.id = "CRGunsmithPanel"
    root:registerAnimationState("default", {leftAnchor=true,topAnchor=true,rightAnchor=false,bottomAnchor=false,left=0,top=0,right=1920,bottom=1080,alpha=1})
    root:animateToState("default", 0)
    do
        local node_cr_title = LUI.UIText.new()
        node_cr_title.id = "cr_title"
        node_cr_title:registerAnimationState("default", {leftAnchor=true,topAnchor=true,rightAnchor=false,bottomAnchor=false,left=92,top=160,right=572,bottom=210,alpha=1})
        node_cr_title:animateToState("default", 0)
        node_cr_title:setText("CUSTOM GUNSMITH")
        if node_cr_title.setRGB then node_cr_title:setRGB(0.961,0.961,0.961) end
        if node_cr_title.setFontSize then node_cr_title:setFontSize(30) end
        root:addElement(node_cr_title)
    end
    do
        local node_cr_option = LUI.UIText.new()
        node_cr_option.id = "cr_option"
        node_cr_option:registerAnimationState("default", {leftAnchor=true,topAnchor=true,rightAnchor=false,bottomAnchor=false,left=92,top=250,right=482,bottom=308,alpha=1})
        node_cr_option:animateToState("default", 0)
        node_cr_option:setText("CUSTOM OPTION")
        if node_cr_option.setRGB then node_cr_option:setRGB(1,1,1) end
        if node_cr_option.setFontSize then node_cr_option:setFontSize(22) end
        if node_cr_option.makeFocusable then node_cr_option:makeFocusable() end
        root:addElement(node_cr_option)
    end
    return root
end
if LUI.MenuBuilder and LUI.MenuBuilder.registerType then
    LUI.MenuBuilder.registerType("CRGunsmithPanel", function(...) return LUI.createMenu["CRGunsmithPanel"](...) end)
end
