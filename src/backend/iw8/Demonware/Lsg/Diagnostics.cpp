#include "Diagnostics.h"

namespace revamped::iw8
{
    namespace
    {
        // V63 keeps the LSG server on a stable stock-range baseline while the
        // redirect/scanner DLL passively records the untouched IW8 0x81 parser
        // ancestry. No client login, task, fence, Source3, or frontend state is written.
        struct PostLoginTaskCensusEntry
        {
            std::uint64_t clientId = 0;
            std::uint64_t firstSeenMs = 0;
            std::uint64_t lastSeenMs = 0;
            std::uint32_t firstCounter = 0;
            std::uint32_t lastCounter = 0;
            std::uint32_t observations = 0;
            std::uint32_t minPayloadBytes = (std::numeric_limits<std::uint32_t>::max)();
            std::uint32_t maxPayloadBytes = 0;
            std::uint64_t firstPayloadFingerprint = 0;
            std::uint64_t lastPayloadFingerprint = 0;
        };

        std::array<PostLoginTaskCensusEntry, 256u * 256u> g_postLoginTaskCensus{};
        std::mutex g_postLoginTaskCensusMutex;
        std::uint64_t g_postLoginCensusStartMs = 0;
        std::uint32_t g_postLoginCensusSequence = 0;
        std::uint32_t g_postLoginCensusUniqueRoutes = 0;

        std::uint64_t Fnv1a64(const std::uint8_t* data, std::size_t size)
        {
            std::uint64_t hash = 14695981039346656037ull;
            for (std::size_t i = 0; i < size; ++i)
            {
                hash ^= static_cast<std::uint64_t>(data[i]);
                hash *= 1099511628211ull;
            }
            return hash;
        }

        std::string HexPreview(const std::uint8_t* data, std::size_t size, std::size_t maxBytes = 64u)
        {
            if (!data || !size)
                return "<empty>";
            const std::size_t take = (std::min)(size, maxBytes);
            std::string out;
            out.reserve(take * 3u + 16u);
            char byteText[4]{};
            for (std::size_t i = 0; i < take; ++i)
            {
                if (i) out.push_back(' ');
                _snprintf_s(byteText, sizeof(byteText), _TRUNCATE, "%02X", static_cast<unsigned>(data[i]));
                out += byteText;
            }
            if (take != size)
                out += " ...";
            return out;
        }

        std::string PrintableRuns(const std::uint8_t* data, std::size_t size,
            std::size_t minimumRun = 4u, std::size_t maxOutput = 1800u)
        {
            if (!data || !size)
                return "<none>";

            std::string out;
            out.reserve((std::min)(size, maxOutput));
            std::size_t i = 0;
            bool first = true;
            while (i < size && out.size() < maxOutput)
            {
                std::size_t start = i;
                while (start < size && (data[start] < 0x20u || data[start] > 0x7Eu))
                    ++start;
                if (start >= size)
                    break;

                std::size_t end = start;
                while (end < size && data[end] >= 0x20u && data[end] <= 0x7Eu)
                    ++end;

                if (end - start >= minimumRun)
                {
                    if (!first)
                        out += " | ";
                    first = false;

                    char prefix[40]{};
                    _snprintf_s(prefix, sizeof(prefix), _TRUNCATE, "@0x%llX=\"",
                        static_cast<unsigned long long>(start));
                    out += prefix;

                    for (std::size_t j = start; j < end && out.size() + 4u < maxOutput; ++j)
                    {
                        const char c = static_cast<char>(data[j]);
                        if (c == '\\' || c == '"')
                            out.push_back('\\');
                        out.push_back(c);
                    }
                    out.push_back('"');
                }

                i = end + 1u;
            }

            return out.empty() ? "<none>" : out;
        }

        void AppendRest255Line(const char* format, ...)
        {
            if (!format)
                return;

            char message[8192]{};
            va_list args;
            va_start(args, format);
            _vsnprintf_s(message, sizeof(message), _TRUNCATE, format, args);
            va_end(args);

            // V88: diagnostics are live CMD output only. No per-feature .log files
            // are created or mirrored into server_emu anymore.
            log::Print("[DW-REST] %s", message);
        }

        void RecordRest255Candidate(std::uint64_t clientId, std::uint32_t counter,
            const std::uint8_t* payload, std::size_t payloadBytes, std::uint64_t fingerprint)
        {
            // V88 performs this observation entirely on the server after
            // decryption. The V86 client-side native task-manager detours were
            // removed after they triggered STATUS_ILLEGAL_INSTRUCTION in stock
            // IW8 1.44. No client executable code is patched by this logger.
            const std::string hex = HexPreview(payload, payloadBytes, payloadBytes);
            const std::string strings = PrintableRuns(payload, payloadBytes);

            AppendRest255Line(
                "REST_REQUEST clientId=%llu counter=%u service=255 task=10 payloadBytes=%llu fingerprint=%016llX mode=SERVER_DECRYPTED_READ_ONLY fullHex={%s}",
                static_cast<unsigned long long>(clientId), counter,
                static_cast<unsigned long long>(payloadBytes),
                static_cast<unsigned long long>(fingerprint), hex.c_str());
            AppendRest255Line(
                "REST_STRINGS clientId=%llu counter=%u printableRuns={%s}",
                static_cast<unsigned long long>(clientId), counter, strings.c_str());
        }

        void AppendPostLoginCensusLine(const char* format, ...)
        {
            if (!format)
                return;

            char message[4096]{};
            va_list args;
            va_start(args, format);
            _vsnprintf_s(message, sizeof(message), _TRUNCATE, format, args);
            va_end(args);

            log::Print("[DW-CENSUS] %s", message);
        }

        void RecordPostLoginTaskCensus(std::uint64_t clientId, std::uint32_t counter,
            const std::vector<std::uint8_t>& plain, const demonware::TaskRequest& request,
            const demonware::TaskRoute* route)
        {
            if (!request.valid || request.payloadOffset > plain.size() ||
                request.payloadBytes > plain.size() - request.payloadOffset)
                return;

            const std::uint8_t* payload = request.payloadBytes ? plain.data() + request.payloadOffset : nullptr;
            const std::uint64_t fingerprint = Fnv1a64(payload, request.payloadBytes);
            const std::string preview = HexPreview(payload, request.payloadBytes);

            if (request.serviceId == 255u && request.taskId == 0x0Au)
                RecordRest255Candidate(clientId, counter, payload, request.payloadBytes, fingerprint);

            const std::uint64_t now = GetTickCount64();
            const std::size_t key = (static_cast<std::size_t>(request.serviceId) << 8u) | request.taskId;

            std::lock_guard<std::mutex> lock(g_postLoginTaskCensusMutex);
            if (!g_postLoginCensusStartMs)
            {
                g_postLoginCensusStartMs = now;
                AppendPostLoginCensusLine("CENSUS_BEGIN mode=PASSIVE_SEMANTIC packetMatching=off guessedReplies=off clientId=%llu",
                    static_cast<unsigned long long>(clientId));
                AppendPostLoginCensusLine("COLUMNS seq elapsedMs clientId counter service task serviceName taskName known replyPolicy observation uniqueRoute payloadBytes minPayload maxPayload fingerprint changed preview");
            }

            auto& entry = g_postLoginTaskCensus[key];
            const bool newRoute = entry.observations == 0;

            if (newRoute)
            {
                entry.clientId = clientId;
                entry.firstSeenMs = now;
                entry.firstCounter = counter;
                entry.minPayloadBytes = static_cast<std::uint32_t>(request.payloadBytes);
                entry.firstPayloadFingerprint = fingerprint;
                ++g_postLoginCensusUniqueRoutes;
            }

            ++entry.observations;
            entry.lastSeenMs = now;
            entry.lastCounter = counter;
            entry.minPayloadBytes = (std::min)(entry.minPayloadBytes, static_cast<std::uint32_t>(request.payloadBytes));
            entry.maxPayloadBytes = (std::max)(entry.maxPayloadBytes, static_cast<std::uint32_t>(request.payloadBytes));
            const bool payloadChanged = entry.observations > 1u && entry.lastPayloadFingerprint != 0u && entry.lastPayloadFingerprint != fingerprint;
            entry.lastPayloadFingerprint = fingerprint;

            const char* policy = "UNMAPPED";
            if (route)
                policy = route->replyPolicy == demonware::ReplyPolicy::None ? "KNOWN_UNIMPLEMENTED" : "SEMANTIC_REPLY";

            const std::uint32_t seq = ++g_postLoginCensusSequence;
            AppendPostLoginCensusLine(
                "TASK seq=%u elapsedMs=%llu clientId=%llu counter=%u service=%u task=%u serviceName=%s taskName=%s known=%s replyPolicy=%s observation=%u uniqueRoute=%s payloadBytes=%llu minPayload=%u maxPayload=%u fingerprint=%016llX changed=%s preview={%s}",
                seq,
                static_cast<unsigned long long>(now - g_postLoginCensusStartMs),
                static_cast<unsigned long long>(clientId), counter,
                static_cast<unsigned>(request.serviceId), static_cast<unsigned>(request.taskId),
                route && route->serviceName ? route->serviceName : "unknown",
                route && route->taskName ? route->taskName : "unknown",
                route ? "yes" : "no", policy, entry.observations,
                newRoute ? "YES" : "no",
                static_cast<unsigned long long>(request.payloadBytes),
                entry.minPayloadBytes, entry.maxPayloadBytes,
                static_cast<unsigned long long>(fingerprint), payloadChanged ? "YES" : "no", preview.c_str());

            if (newRoute || entry.observations == 2u || (entry.observations % 5u) == 0u)
            {
                AppendPostLoginCensusLine(
                    "SUMMARY uniqueRoutes=%u totalObservations=%u last={service:%u task:%u counter:%u observations:%u firstCounter:%u lastCounter:%u firstMs:%llu lastMs:%llu} correlationKey=counter+service+task",
                    g_postLoginCensusUniqueRoutes, g_postLoginCensusSequence,
                    static_cast<unsigned>(request.serviceId), static_cast<unsigned>(request.taskId), counter,
                    entry.observations, entry.firstCounter, entry.lastCounter,
                    static_cast<unsigned long long>(entry.firstSeenMs - g_postLoginCensusStartMs),
                    static_cast<unsigned long long>(entry.lastSeenMs - g_postLoginCensusStartMs));
            }
        }

        void AppendLsgPipelineV63(const char* format, ...)
        {
            if (!format)
                return;

            char message[2048]{};
            va_list args;
            va_start(args, format);
            _vsnprintf_s(message, sizeof(message), _TRUNCATE, format, args);
            va_end(args);

            // V88 CMD-only research output. No lsg_pipeline_v63.log mirror.
            log::Print("[LSG-V63] %s", message);
        }
    }
}
