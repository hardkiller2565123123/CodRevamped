#pragma once

#include "BgsRpc.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace revamped::iw8::bgs
{
    // Descriptor-free protobuf observation used by the compatibility layer.
    // It intentionally records message SHAPE rather than packet bytes: field
    // number, wire type, repetition/order, numeric values, and byte lengths.
    // Length-delimited contents are not printed so tickets/credentials remain
    // out of semantic compatibility logs.
    struct ProtoFieldObservation
    {
        std::uint32_t number = 0;
        std::uint32_t wireType = 0;
        std::uint64_t numericValue = 0;
        std::size_t byteLength = 0;
    };

    struct ProtoMessageObservation
    {
        bool valid = false;
        std::vector<ProtoFieldObservation> fields;
        std::uint64_t shapeHash = 0;
        std::string error;
    };

    bool ObserveProtoMessage(const Byte* data, std::size_t size, ProtoMessageObservation& out);
    std::string DescribeProtoMessage(const ProtoMessageObservation& observation, std::size_t maxFields = 24);
}
