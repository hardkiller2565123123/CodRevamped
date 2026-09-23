#pragma once
#include "../../core/Main.hpp"
#include <deque>
#include <string>
#include <vector>

struct game_console
{
    bool bopen = false;
    int start = 0;
    char szBuffer[4096]{};
    int edit_tick = 0;

    void Render();
    void TickInput();
    void KeyboardHandle(WPARAM wParam, int key, char chKey);
    void Print(const std::string& text);
    void Clear();

private:
    uintptr_t ResolveFont() const;
    void ExecuteBuffer();
    void AppendCharacter(char value);
    void RecallHistory(int direction);

    std::deque<std::string> output_;
    std::vector<std::string> history_;
    int history_index_ = -1;
};

extern game_console g_console;
