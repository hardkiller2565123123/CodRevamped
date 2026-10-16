#pragma once
// Read-only high-signal timeline extraction from a CodRevamped 1.20 log.
// Does not interpret a lobby teardown as proof of a specific crash cause.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <istream>
#include <string>
#include <vector>

namespace codrevamped::mwassetlab::loading {
struct Event { std::uint32_t line = 0; std::string type; std::string detail; };
struct Timeline { std::string source; std::uint32_t lines = 0; bool truncated = false;
    std::vector<Event> events; };
inline const char* Classify(const std::string& s) noexcept {
    if (s.find("[LOAD120]")!=std::string::npos) return "native-launch-observation";
    if (s.find("[BOT120-LAUNCH-CHECK]")!=std::string::npos) return "native-ready-or-start-result";
    if (s.find("[BOT120-LAUNCH]")!=std::string::npos) return "native-start-request";
    if (s.find("[BOT120-STAGE]")!=std::string::npos) return "frontend-lobby-transition";
    if (s.find("[BOT120-SV]")!=std::string::npos) return "native-bot-assignment";
    if (s.find("[BOT120-ROSTER]")!=std::string::npos) return "staged-lobby-roster";
    if (s.find("[FF120-MODE]")!=std::string::npos) return "collision-mode-selection";
    if (s.find("[FF120]")!=std::string::npos) return "file-read-probe";
    if (s.find("[LSG-ROUTE]")!=std::string::npos && s.find("matchmaker-lobby-disbanded")!=std::string::npos)
        return "server-lobby-disband";
    if (s.find("[LSG-ROUTE]")!=std::string::npos && s.find("matchmaker-host-document-updated")!=std::string::npos)
        return "backend-host-document-update";
    if (s.find("[LSG-ROUTE]")!=std::string::npos && s.find("matchmaker-search-created")!=std::string::npos)
        return "backend-match-search-created";
    return nullptr;
}
inline Timeline Parse(std::istream& input, const std::string& source,
                      std::size_t maxLines=250000, std::size_t maxEvents=500) {
    Timeline result;result.source=source;
    std::string line;
    while (result.lines<maxLines && std::getline(input,line)) {
        ++result.lines;
        if (const char* type=Classify(line)) {
            if (result.events.size()>=maxEvents) {result.truncated=true;break;}
            // Upper-bound output size even for malformed or hostile log lines.
            if (line.size()>320) line.resize(320);
            result.events.push_back({result.lines,type,std::move(line)});
        }
    }
    if (result.lines>=maxLines && !input.eof()) result.truncated=true;
    return result;
}
}
