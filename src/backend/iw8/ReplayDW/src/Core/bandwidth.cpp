#include "host_os.h"
#include "bandwidth.h"
#include "wire.h"
#include "network.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <mutex>
#include <thread>

namespace bandwidth
{
    namespace
    {
        using Clock = std::chrono::steady_clock;
        constexpr uint32_t packetBytes = 1200, packetCount = 256;
        constexpr uint32_t initialWaitMs = 50, uploadMs = 300, firstDownloadTimeoutMs = 1500;
        constexpr uint32_t downloadMs = 300, downloadIdleMs = 100;
        constexpr auto lifetime = std::chrono::seconds(8);

        Reply error(uint16_t code, const char *operation)
        {
            crypto::Bytes data{1};
            wire::raw(data, code);
            return {std::move(data), operation, {}};
        }

        struct Results
        {
            uint32_t bytes = 0, milliseconds = 0, meanSequence = 0, minimumSequence = 0,
                     maximumSequence = 0;

            void write(crypto::Bytes &data) const
            {
                wire::raw(data, bytes);
                wire::raw(data, milliseconds);
                wire::raw(data, meanSequence);
                wire::raw(data, minimumSequence);
                wire::raw(data, maximumSequence);
            }
        };
    } // namespace

    struct Session::State
    {
        SOCKET socket = INVALID_SOCKET;
        uint16_t port = 0;
        std::array<uint8_t, 8> token{};
        uint8_t mode = 0;
        std::mutex mutex;
        Results upload;
        unsigned received = 0, sent = 0;
        bool workerFailed = false;
        std::jthread worker;

        explicit State(uint8_t testMode) : mode(testMode)
        {
            const auto random = crypto::random(static_cast<unsigned>(token.size()));
            std::copy(random.begin(), random.end(), token.begin());
            socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (socket == INVALID_SOCKET)
                throw std::runtime_error("Bandwidth UDP socket creation failed");
            sockaddr_in address{};
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = network::bindAddress();
            const auto firstPort = network::bandwidthPort();
            const auto candidates = firstPort ? network::bandwidthPortCount() : 1;
            bool bound = false;
            for (unsigned index = 0; index < candidates; ++index)
            {
                address.sin_port = htons(static_cast<uint16_t>(firstPort + index));
                if (!bind(socket, reinterpret_cast<sockaddr *>(&address), sizeof(address)))
                {
                    bound = true;
                    break;
                }
#ifdef _WIN32
                if (WSAGetLastError() != WSAEADDRINUSE)
#else
                if (WSAGetLastError() != EADDRINUSE)
#endif
                    break;
            }
            int addressSize = sizeof(address);
            if (!bound || getsockname(socket, reinterpret_cast<sockaddr *>(&address), &addressSize))
            {
                closesocket(socket);
                socket = INVALID_SOCKET;
                throw std::runtime_error("Bandwidth UDP port pool exhausted or bind failed");
            }
            port = ntohs(address.sin_port);
            const int receiveBytes = 512 * 1024;
            setsockopt(socket,
                       SOL_SOCKET,
                       SO_RCVBUF,
                       reinterpret_cast<const char *>(&receiveBytes),
                       sizeof(receiveBytes));
            try
            {
                worker = std::jthread(
                    [this](std::stop_token stop)
                    {
                        run(stop);
                    });
            }
            catch (...)
            {
                closesocket(socket);
                socket = INVALID_SOCKET;
                throw;
            }
        }

        ~State()
        {
            worker.request_stop();
            if (worker.joinable())
                worker.join();
            if (socket != INVALID_SOCKET)
                closesocket(socket);
            SecureZeroMemory(token.data(), token.size());
        }

        void run(std::stop_token stop) noexcept
        {
            // Port and nonce are given only over the authenticated lobby. Accept a
            // single loopback sender, deduplicate counters, and cap the send volume.
            // This measures the local path; it does not represent Internet capacity.
            sockaddr_in peer{};
            bool havePeer = false;
            std::array<bool, packetCount> seen{};
            std::array<uint8_t, packetBytes + 1> packet{};
            const auto started = Clock::now();
            auto first = started;
            uint64_t sequenceSum = 0;
            unsigned nextDownload = 0;
            while (!stop.stop_requested() && Clock::now() - started < lifetime)
            {
                fd_set readable{};
                FD_SET(socket, &readable);
                timeval wait{0, 2000};
                const int ready = select(0, &readable, nullptr, nullptr, &wait);
                if (ready == SOCKET_ERROR)
                {
                    std::lock_guard lock(mutex);
                    workerFailed = true;
                    return;
                }
                if (ready)
                {
                    sockaddr_in sender{};
                    int senderSize = sizeof(sender);
                    const int size = recvfrom(socket,
                                              reinterpret_cast<char *>(packet.data()),
                                              static_cast<int>(packet.size()),
                                              0,
                                              reinterpret_cast<sockaddr *>(&sender),
                                              &senderSize);
                    if (size == SOCKET_ERROR && WSAGetLastError() != WSAEMSGSIZE)
                    {
                        std::lock_guard lock(mutex);
                        workerFailed = true;
                        return;
                    }
                    if (size == static_cast<int>(packetBytes) && sender.sin_family == AF_INET &&
                        network::permittedPeer(sender.sin_addr.s_addr) &&
                        std::equal(token.begin(), token.end(), packet.begin() + 4))
                    {
                        uint32_t sequence = 0;
                        std::memcpy(&sequence, packet.data(), sizeof(sequence));
                        const auto now = Clock::now();
                        if (sequence < packetCount &&
                            (!havePeer || (peer.sin_port == sender.sin_port &&
                                           peer.sin_addr.s_addr == sender.sin_addr.s_addr)))
                        {
                            if (!havePeer)
                            {
                                peer = sender;
                                havePeer = true;
                                first = now;
                            }
                            if (now - first <= std::chrono::milliseconds(uploadMs + 100) &&
                                !seen[sequence])
                            {
                                seen[sequence] = true;
                                std::lock_guard lock(mutex);
                                if (!received)
                                    upload.minimumSequence = upload.maximumSequence = sequence;
                                ++received;
                                sequenceSum += sequence;
                                upload.bytes += packetBytes + 8;
                                upload.milliseconds = static_cast<uint32_t>(std::max<int64_t>(
                                    1,
                                    std::chrono::duration_cast<std::chrono::milliseconds>(now -
                                                                                          first)
                                        .count()));
                                upload.meanSequence = static_cast<uint32_t>(sequenceSum / received);
                                upload.minimumSequence = std::min(upload.minimumSequence, sequence);
                                upload.maximumSequence = std::max(upload.maximumSequence, sequence);
                            }
                        }
                    }
                }
                if (!havePeer)
                    continue;
                if (mode == 0 && Clock::now() - first > std::chrono::milliseconds(uploadMs + 100))
                    return;
                if (mode != 1)
                    continue;
                const auto downloadStart = first + std::chrono::milliseconds(uploadMs + 100);
                auto now = Clock::now();
                while (nextDownload < packetCount &&
                       now >= downloadStart +
                                  std::chrono::microseconds(uint64_t(nextDownload) * downloadMs *
                                                            1000 / packetCount))
                {
                    std::array<uint8_t, packetBytes> down{};
                    std::memcpy(down.data(), &nextDownload, sizeof(nextDownload));
                    std::copy(token.begin(), token.end(), down.begin() + 4);
                    const int size = sendto(socket,
                                            reinterpret_cast<const char *>(down.data()),
                                            static_cast<int>(down.size()),
                                            0,
                                            reinterpret_cast<const sockaddr *>(&peer),
                                            sizeof(peer));
                    if (size != static_cast<int>(down.size()))
                    {
                        std::lock_guard lock(mutex);
                        workerFailed = true;
                        return;
                    }
                    ++nextDownload;
                    {
                        std::lock_guard lock(mutex);
                        ++sent;
                    }
                    now = Clock::now();
                }
                if (nextDownload == packetCount &&
                    now > downloadStart + std::chrono::milliseconds(downloadMs + 1000))
                    return;
            }
        }
    };

    Session::Session() = default;
    Session::~Session() = default;

    Reply Session::dispatch(std::span<const uint8_t> request)
    {
        if (request.size() == 16 && request[0] == 0)
        {
            // Native start 0x142130860 initializes only these two bytes. Do not
            // interpret or persist the remaining 14 bytes of caller stack padding.
            if (request[1] > 1 || attempts_ >= 8)
                return error(106, "bandwidth-begin-invalid");
            ++attempts_;
            state_.reset();
            try
            {
                state_ = std::make_unique<State>(request[1]);
            }
            catch (const std::exception &)
            {
                return error(102, "bandwidth-provider-unavailable");
            }
            crypto::Bytes data{0};
            // 0x14212FCE0: seven raw u32s, host-order port, network-order IPv4,
            // eight nonce bytes. All timing intervals are milliseconds.
            for (const auto value : {packetBytes,
                                     packetCount,
                                     initialWaitMs,
                                     uploadMs,
                                     firstDownloadTimeoutMs,
                                     downloadMs,
                                     downloadIdleMs})
                wire::raw(data, value);
            wire::raw(data, state_->port);
            wire::raw(data, network::advertisedAddress());
            data.insert(data.end(), state_->token.begin(), state_->token.end());
            return {std::move(data),
                    "bandwidth-begin",
                    " path=loopback packets=" + std::to_string(packetCount)};
        }
        if (request.size() == 21 && request[0] == 1)
        {
            if (!state_)
                return error(106, "bandwidth-report-without-begin");
            const auto reportedBytes = wire::at<uint32_t>(request, 1);
            const auto reportedMs = wire::at<uint32_t>(request, 5);
            // Bounds cover the complete native 20-byte download result, including
            // empty measurements. No client-supplied upload result is trusted.
            if (reportedBytes > packetCount * (packetBytes + 8) ||
                reportedBytes % (packetBytes + 8) || reportedMs > 8000)
                return error(106, "bandwidth-report-invalid");
            for (size_t offset : {size_t(9), size_t(13), size_t(17)})
                if (wire::at<uint32_t>(request, offset) >= packetCount)
                    return error(106, "bandwidth-report-invalid");
            Results upload;
            unsigned received = 0, sent = 0;
            bool failed = false;
            {
                std::lock_guard lock(state_->mutex);
                upload = state_->upload;
                received = state_->received;
                sent = state_->sent;
                failed = state_->workerFailed;
            }
            state_.reset();
            if (failed)
                return error(102, "bandwidth-provider-failed");
            crypto::Bytes data{0};
            upload.write(data);
            return {std::move(data),
                    "bandwidth-measured",
                    " path=loopback upload_packets=" + std::to_string(received) +
                        " download_packets=" + std::to_string(sent) +
                        " client_download_bytes=" + std::to_string(reportedBytes) +
                        " upload_elapsed_ms=" + std::to_string(upload.milliseconds)};
        }
        return error(106, "bandwidth-request-invalid");
    }
} // namespace bandwidth
