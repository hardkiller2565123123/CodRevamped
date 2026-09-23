#pragma once
#include <string>

namespace lan_profile_research
{
    std::string LanStatus();
    std::string ProfileStatus();

    bool SetLanNetworkMode(bool lan, std::string& message);
    bool SetSessionMode(int mode, std::string& message);

    bool WriteLanResearchReport(std::string& message);
    bool InspectLanFunctions(std::string& message);
    bool ScanSystemlinkXrefs(std::string& message);
    bool DumpProfile(std::string& message);
    bool AnalyzeProfile(std::string& message);

    // NET_CreateSession / Party_StartLANServerJoin are intentionally unresolved
    // in this phase. These helpers only report/log readiness and never fabricate
    // session structures.
    bool HostResearch(std::string& message);
    bool SessionResearch(std::string& message);
    bool JoinResearch(const std::string& sessionData, std::string& message);
}
