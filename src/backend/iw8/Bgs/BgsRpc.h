#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace revamped::iw8::bgs
{
    using Byte = std::uint8_t;

    struct RpcHeader
    {
        bool valid = false;
        bool hasServiceId = false;
        bool hasMethodId = false;
        bool hasToken = false;
        bool hasSize = false;
        bool hasStatus = false;
        bool hasServiceHash = false;
        std::uint32_t serviceId = 0;
        std::uint32_t methodId = 0;
        std::uint32_t token = 0;
        std::uint32_t size = 0;
        std::uint32_t status = 0;
        std::uint32_t serviceHash = 0;
    };

    struct RpcEnvelope
    {
        RpcHeader header;
        std::vector<Byte> body;
        std::uint16_t headerSize = 0;
    };

    struct EntityId
    {
        std::uint64_t high = 0;
        std::uint64_t low = 0;
        bool valid = false;
    };

    bool ReadProtoVarint(const Byte* data, std::size_t size, std::size_t& offset, std::uint64_t& value);
    bool ParseRpcHeader(const Byte* data, std::size_t size, RpcHeader& out);
    bool ParseRpcPayload(const std::vector<Byte>& payload, RpcEnvelope& out);

    bool TryGetVarintField(const Byte* data, std::size_t size, std::uint32_t wantedField, std::uint64_t& valueOut);
    bool TryGetBytesField(const Byte* data, std::size_t size, std::uint32_t wantedField, std::vector<Byte>& valueOut);
    bool TryGetBytesFields(const Byte* data, std::size_t size, std::uint32_t wantedField, std::vector<std::vector<Byte>>& valuesOut);
    bool TryGetFixed32Field(const Byte* data, std::size_t size, std::uint32_t wantedField, std::uint32_t& valueOut);
    bool TryGetFixed64Field(const Byte* data, std::size_t size, std::uint32_t wantedField, std::uint64_t& valueOut);
    bool TryGetEntityIdField(const Byte* data, std::size_t size, std::uint32_t wantedField, EntityId& valueOut);

    void AppendVarint(std::vector<Byte>& out, std::uint64_t value);
    void AppendKey(std::vector<Byte>& out, std::uint32_t field, std::uint32_t wire);
    void AppendVarintField(std::vector<Byte>& out, std::uint32_t field, std::uint64_t value);
    void AppendFixed32Field(std::vector<Byte>& out, std::uint32_t field, std::uint32_t value);
    void AppendFixed64Field(std::vector<Byte>& out, std::uint32_t field, std::uint64_t value);
    void AppendBytesField(std::vector<Byte>& out, std::uint32_t field, const void* data, std::size_t size);
    void AppendBytesField(std::vector<Byte>& out, std::uint32_t field, const std::vector<Byte>& value);
    void AppendStringField(std::vector<Byte>& out, std::uint32_t field, const std::string& value);
    void AppendEntityIdField(std::vector<Byte>& out, std::uint32_t field, const EntityId& value);

    std::vector<Byte> BuildResponsePayload(std::uint32_t token, const std::vector<Byte>& body, std::uint32_t status = 0);
    std::vector<Byte> BuildRequestPayload(std::uint32_t serviceHash, std::uint32_t methodId,
        std::uint32_t token, const std::vector<Byte>& body);

    const char* StatusName(std::uint32_t status);
    std::uint64_t UnixTimeMilliseconds();
}
