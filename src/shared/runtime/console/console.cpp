#include "console.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

namespace
{
    bool KeyPressed(int key)
    {
        // Use high-bit edge detection instead of GetAsyncKeyState's global low bit.
        // The game can consume the low bit before our render callback sees it.
        static bool previous[256]{};
        if (key < 0 || key >= 256)
            return false;

        const bool down = (GetAsyncKeyState(key) & 0x8000) != 0;
        const bool pressed = down && !previous[key];
        previous[key] = down;
        return pressed;
    }

    bool IsReadablePointer(uintptr_t address)
    {
        if (!address)
            return false;
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)))
            return false;
        return mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD));
    }

    char TranslateKey(int key, bool shift)
    {
        if (key >= 'A' && key <= 'Z')
            return static_cast<char>(shift ? key : std::tolower(key));
        if (key >= '0' && key <= '9')
        {
            static const char shifted[] = ")!@#$%^&*(";
            return shift ? shifted[key - '0'] : static_cast<char>(key);
        }
        switch (key)
        {
        case VK_SPACE: return ' ';
        case VK_OEM_MINUS: return shift ? '_' : '-';
        case VK_OEM_PLUS: return shift ? '+' : '=';
        case VK_OEM_PERIOD: return shift ? '>' : '.';
        case VK_OEM_COMMA: return shift ? '<' : ',';
        case VK_OEM_2: return shift ? '?' : '/';
        case VK_OEM_1: return shift ? ':' : ';';
        case VK_OEM_7: return shift ? '"' : '\'';
        case VK_OEM_4: return shift ? '{' : '[';
        case VK_OEM_6: return shift ? '}' : ']';
        case VK_OEM_5: return shift ? '|' : '\\';
        default: return 0;
        }
    }
}

uintptr_t game_console::ResolveFont() const
{
    if (g_Addrs.watermark_font && IsReadablePointer(g_Addrs.watermark_font))
    {
        const auto font = *reinterpret_cast<const uintptr_t*>(g_Addrs.watermark_font);
        if (IsReadablePointer(font))
            return font;
    }

    if (g_Addrs.UI_GetFontHandle && g_Addrs.ScrPlace_GetViewUIContext)
    {
        const auto placement = ScrPlace_GetViewUIContext(0);
        if (placement)
        {
            const auto font = UI_GetFontHandle(placement, 7, 1.0f);
            if (font)
                return font;
        }
    }

    return 0;
}

void game_console::Print(const std::string& text)
{
    output_.push_back(text);
    while (output_.size() > 128)
        output_.pop_front();
    std::printf("[INGAME-CONSOLE] %s\n", text.c_str());
}

void game_console::Clear()
{
    output_.clear();
}

void game_console::AppendCharacter(char value)
{
    if (!value)
        return;
    const size_t length = std::strlen(szBuffer);
    if (length + 1 >= sizeof(szBuffer))
        return;
    szBuffer[length] = value;
    szBuffer[length + 1] = '\0';
}

void game_console::RecallHistory(int direction)
{
    if (history_.empty())
        return;

    if (history_index_ < 0)
        history_index_ = static_cast<int>(history_.size());
    history_index_ = (std::max)(0, (std::min)(static_cast<int>(history_.size()) - 1, history_index_ + direction));
    strncpy_s(szBuffer, history_[static_cast<size_t>(history_index_)].c_str(), _TRUNCATE);
}

void game_console::ExecuteBuffer()
{
    std::string command = szBuffer;
    if (command.empty())
        return;

    Print(std::string("> ") + command);
    history_.push_back(command);
    if (history_.size() > 64)
        history_.erase(history_.begin());
    history_index_ = -1;

    if (command == "clear")
    {
        Clear();
    }
    else
    {
        if (command.back() != '\n')
            command.push_back('\n');

        if (g_Addrs.Cbuf_AddText)
        {
            auto function = reinterpret_cast<void(*)(int, const char*)>(g_Addrs.Cbuf_AddText);
            function(0, command.c_str());
        }
        else
        {
            Print("Validated Cbuf_AddText is unresolved. Legacy command execution is disabled to prevent crashes.");
        }
    }

    szBuffer[0] = '\0';
}

void game_console::TickInput()
{
    if (KeyPressed(VK_OEM_3))
    {
        bopen = !bopen;
        if (bopen)
            Print("T9 in-game console opened. Enter executes, Up/Down recalls history, Esc closes.");
        return;
    }

    if (!bopen)
        return;

    if (KeyPressed(VK_ESCAPE))
    {
        bopen = false;
        return;
    }
    if (KeyPressed(VK_RETURN))
    {
        ExecuteBuffer();
        return;
    }
    if (KeyPressed(VK_BACK))
    {
        const size_t length = std::strlen(szBuffer);
        if (length)
            szBuffer[length - 1] = '\0';
    }
    if (KeyPressed(VK_UP))
        RecallHistory(-1);
    if (KeyPressed(VK_DOWN))
        RecallHistory(1);

    const bool shift = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
    for (int key = 'A'; key <= 'Z'; ++key)
        if (KeyPressed(key)) AppendCharacter(TranslateKey(key, shift));
    for (int key = '0'; key <= '9'; ++key)
        if (KeyPressed(key)) AppendCharacter(TranslateKey(key, shift));

    const int punctuation[] = { VK_SPACE, VK_OEM_MINUS, VK_OEM_PLUS, VK_OEM_PERIOD, VK_OEM_COMMA,
        VK_OEM_2, VK_OEM_1, VK_OEM_7, VK_OEM_4, VK_OEM_6, VK_OEM_5 };
    for (int key : punctuation)
        if (KeyPressed(key)) AppendCharacter(TranslateKey(key, shift));
}

void game_console::Render()
{
    if (!bopen)
        return;

    if (!g_Addrs.shader_white || !g_Addrs.R_AddCmdDrawStretchPic ||
        !g_Addrs.CL_DrawTextPhysical || !g_Addrs.R_TextWidth)
        return;

    const uintptr_t font = ResolveFont();
    if (!font)
        return;

    uintptr_t shader = 0;
    if (IsReadablePointer(g_Addrs.shader_white))
        shader = *reinterpret_cast<const uintptr_t*>(g_Addrs.shader_white);
    if (!shader)
        return;

    float border[4] = { 0.08f, 0.08f, 0.08f, 0.97f };
    float body[4] = { 0.02f, 0.02f, 0.02f, 0.92f };
    float input[4] = { 0.14f, 0.14f, 0.14f, 0.98f };
    float white[4] = { 1.0f, 1.0f, 1.0f, 1.0f };
    float accent[4] = { 0.95f, 0.78f, 0.22f, 1.0f };

    const float x = 28.0f;
    const float y = 34.0f;
    const float width = 1500.0f;
    const float height = 430.0f;
    const float scale = 0.55f;

    R_AddCmdDrawStretchPic(x, y, width, height, 0, 0, 1, 1, border, shader);
    R_AddCmdDrawStretchPic(x + 2, y + 2, width - 4, height - 4, 0, 0, 1, 1, body, shader);
    R_AddCmdDrawStretchPic(x + 8, y + height - 48, width - 16, 38, 0, 0, 1, 1, input, shader);

    CL_DrawTextPhysical("T9 Developer Console", 0x7FFFFFFF, font, x + 14, y + 28, scale, scale, 0.0f, accent, 0, 0);

    const size_t visible = 14;
    const size_t first = output_.size() > visible ? output_.size() - visible : 0;
    float lineY = y + 55;
    for (size_t i = first; i < output_.size(); ++i)
    {
        CL_DrawTextPhysical(output_[i].c_str(), 0x7FFFFFFF, font, x + 14, lineY, scale, scale, 0.0f, white, 0, 0);
        lineY += 23.0f;
    }

    std::string prompt = "] ";
    prompt += szBuffer;
    CL_DrawTextPhysical(prompt.c_str(), 0x7FFFFFFF, font, x + 18, y + height - 22, scale, scale, 0.0f, white, 0, 0);

    const float cursorX = x + 18 + R_TextWidth(0, prompt.c_str(), 0x7FFFFFFF, font) * scale;
    if ((edit_tick++ / 25) % 2 == 0)
        CL_DrawTextPhysical("|", 0x7FFFFFFF, font, cursorX, y + height - 22, scale, scale, 0.0f, white, 0, 0);
}

void game_console::KeyboardHandle(WPARAM, int key, char chKey)
{
    if (key == VK_RETURN)
        ExecuteBuffer();
    else if (key == VK_BACK)
    {
        const size_t length = std::strlen(szBuffer);
        if (length) szBuffer[length - 1] = '\0';
    }
    else
        AppendCharacter(chKey);
}

game_console g_console;
