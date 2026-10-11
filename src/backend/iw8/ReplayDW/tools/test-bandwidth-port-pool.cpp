#include "../src/host_os.h"
#include "../src/network.h"
#include "../src/bandwidth.h"
#include "../src/wire.h"
#include "../third_party/nlohmann/json.hpp"
#include <fstream>
#include <iostream>
#include <thread>

namespace
{
    void require(bool value)
    {
        if (!value)
            throw std::runtime_error("Bandwidth port-pool contract failed");
    }
} // namespace

int main(int argc, char **argv)
{
    try
    {
        require(argc == 2);
        const std::filesystem::path directory(argv[1]);
        require(!std::filesystem::exists(directory));
        std::filesystem::create_directories(directory);
        const auto publish = [&](unsigned count)
        {
            const nlohmann::json config = {{"schema", 1},
                                           {"bind_address", "127.0.0.1"},
                                           {"advertised_address", "127.0.0.1"},
                                           {"qos_port", 32116},
                                           {"relay_port", 32117},
                                           {"bandwidth_port", 32118},
                                           {"bandwidth_port_count", count},
                                           {"clients", nlohmann::json::object()}};
            std::ofstream file(directory / "network.json");
            file << config;
            require(bool(file.flush()));
        };
        publish(2);
        network::initialize(directory);
        WSADATA wsa{};
        require(!WSAStartup(MAKEWORD(2, 2), &wsa));
        const network::PeerScope peer(htonl(INADDR_LOOPBACK));
        bandwidth::Session first, second, third;
        const std::array<uint8_t, 16> begin{};
        const auto firstReply = first.dispatch(begin);
        const auto secondReply = second.dispatch(begin);
        require(firstReply.data.size() == 43 && secondReply.data.size() == 43 &&
                !firstReply.data[0] && !secondReply.data[0]);
        const auto firstPort = wire::at<uint16_t>(firstReply.data, 29);
        const auto secondPort = wire::at<uint16_t>(secondReply.data, 29);
        require(firstPort == 32118 && secondPort == 32119);
        const auto exhausted = third.dispatch(begin);
        require(exhausted.data.size() == 3 && exhausted.data[0] == 1 &&
                wire::at<uint16_t>(exhausted.data, 1) == 102);
        const auto socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        require(socket != INVALID_SOCKET);
        std::array<uint8_t, 1200> packet{};
        std::copy(secondReply.data.begin() + 35, secondReply.data.end(), packet.begin() + 4);
        sockaddr_in destination{};
        destination.sin_family = AF_INET;
        destination.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        // The second player's token on the first socket must never count.
        for (const auto port : {firstPort, secondPort})
        {
            destination.sin_port = htons(port);
            require(sendto(socket,
                           reinterpret_cast<const char *>(packet.data()),
                           packet.size(),
                           0,
                           reinterpret_cast<const sockaddr *>(&destination),
                           sizeof(destination)) == static_cast<int>(packet.size()));
        }
        closesocket(socket);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::array<uint8_t, 21> report{};
        report[0] = 1;
        const auto firstReport = first.dispatch(report);
        const auto secondReport = second.dispatch(report);
        require(firstReport.data.size() == 21 && secondReport.data.size() == 21 &&
                !firstReport.data[0] && !secondReport.data[0]);
        require(wire::at<uint32_t>(firstReport.data, 1) == 0 &&
                wire::at<uint32_t>(secondReport.data, 1) == 1208);
        const auto reclaimed = third.dispatch(begin);
        require(reclaimed.data.size() == 43 && !reclaimed.data[0] &&
                wire::at<uint16_t>(reclaimed.data, 29) == firstPort);
        publish(33);
        bool rejected = false;
        try
        {
            network::initialize(directory);
        }
        catch (const std::exception &)
        {
            rejected = true;
        }
        require(rejected);
        std::cout << "PASS: parallel allocation, bounded exhaustion, token isolation, measured UDP "
                     "bytes, port reclamation, invalid pool rejected\n";
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
