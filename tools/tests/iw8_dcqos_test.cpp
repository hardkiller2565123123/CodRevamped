#include "../../src/backend/iw8/Demonware/DemonwareTaskRouter.cpp"
#include <cassert>
#include <iostream>

int main()
{
    using namespace revamped::iw8::demonware;
    {
        const auto* inventory = FindTaskRoute(80, 69);
        assert(inventory);
        TaskRequest req;
        req.valid = true; req.serviceId = 80; req.taskId = 69;
        const std::vector<std::uint8_t> payload = {23,8,11,0,0,0,10,4,'5','8','0','0',18,0,24,238,5,0};
        std::vector<std::uint8_t> reply;
        assert(BuildTaskReply(*inventory, req, payload.data(), payload.size(), 100, reply));
        std::vector<std::uint8_t> account, body, expected;
        AppendPbU64(account, 1, 1); AppendPbString(account, 2, "bnet");
        AppendPbObject(body, 1, account); AppendPbString(body, 2, "5800");
        AppendPbString(body, 3, "");
        BuildLegacyTaskEnvelope(expected, 100, 69); AppendTypedStruct(expected, body);
        std::vector<std::uint8_t> wire; FinishLegacyTaskReply(expected, wire);
        assert(reply == wire);
        assert(!BuildTaskReply(*inventory, req, payload.data(), 8, 100, reply));
    }
    assert(revamped::iw8::localpublisher::ManifestBody().size() == 586);
    assert(revamped::iw8::localpublisher::IsManifest("1_manifest_patch_pc_8.19.txt"));
    assert(revamped::iw8::localpublisher::IsManifest("1_manifest_comms_pc_8.19.txt"));
    assert(!revamped::iw8::localpublisher::IsManifest("../1_manifest_patch_pc_8.19.txt"));
    assert(!revamped::iw8::localpublisher::IsManifest("1_manifest_patch_pc_9.0.txt"));
    const auto manifestMetadata = BuildLocalPublisherMetadataJson(
        "infinityward", "1_manifest_patch_pc_8.19.txt", "5800");
    assert(manifestMetadata.find("\"contentLength\":586") != std::string::npos);
    assert(manifestMetadata.find("\"objectID\":120001") != std::string::npos);
    assert(manifestMetadata.find(revamped::iw8::localpublisher::ManifestChecksum) != std::string::npos);
    assert(std::strlen(revamped::iw8::localpublisher::ManifestChecksum) == 28);
    const auto* route = FindTaskRoute(145, 25);
    assert(route && std::string(route->taskName) == "initiateDCQoS");
    TaskRequest request;
    request.valid = true;
    request.serviceId = 145;
    request.taskId = 25;
    const std::string params =
        "{\"qos_build_name_context\":\"shared_qos\",\"qos_build_name\":\"relayping-all-all-all-3\"}";
    std::vector<std::uint8_t> payload{0x10};
    payload.insert(payload.end(), params.begin(), params.end());
    payload.push_back(0);
    std::vector<std::uint8_t> reply;
    assert(BuildTaskReply(*route, request, payload.data(), payload.size(), 123, reply));

    // Independently construct the wire contract, including result counts.
    const std::string expectedJson = "{\"num_probes\":1,\"transaction_id\":123,\"hosts\":[]}";
    std::vector<std::uint8_t> body{
        0x0a,123,0,0,0,0,0,0,0, // typed transaction
        0x08,0,0,0,0,           // BD_NO_ERROR
        0x03,25,                // typed task ID
        0x08,1,0,0,0,           // numResults
        0x08,1,0,0,0,           // totalNumResults
        0x10};
    body.insert(body.end(), expectedJson.begin(), expectedJson.end());
    body.push_back(0);
    std::vector<std::uint8_t> expected{
        static_cast<std::uint8_t>(body.size()),0,0,0,1};
    expected.insert(expected.end(), body.begin(), body.end());
    expected.resize((expected.size()+15u)&~std::size_t(15),0);
    assert(reply == expected);
    payload.push_back(0); // observed task terminator is optional
    assert(BuildTaskReply(*route, request, payload.data(), payload.size(), 123, reply));
    payload.back() = 1;
    assert(!BuildTaskReply(*route, request, payload.data(), payload.size(), 123, reply));
    payload.resize(payload.size()-2); // missing string NUL
    assert(!BuildTaskReply(*route, request, payload.data(), payload.size(), 123, reply));
    assert(!BuildTaskReply(*route, request, nullptr, 1, 123, reply));
    const std::uint8_t malformed[] = {0x10,'{','}',0};
    assert(!BuildTaskReply(*route, request, malformed, sizeof(malformed), 123, reply));
    request.taskId = 26;
    assert(!BuildTaskReply(*route, request, malformed, sizeof(malformed), 123, reply));
    // No accidental token or relay success route.
    assert(FindTaskRoute(145, 24)->replyPolicy == ReplyPolicy::LegacyUnsupported);
    const auto* unsupported = FindTaskRoute(145, 26);
    assert(unsupported->replyPolicy == ReplyPolicy::LegacyUnsupported);
    request.taskId = 26;
    assert(BuildTaskReply(*unsupported, request, nullptr, 0, 125, reply));
    assert(reply[14] == 8 && reply[15] == 108); // typed error, not success
    const auto* completion = FindTaskRoute(145, 4);
    assert(completion);
    request.taskId = 4;
    std::vector<std::uint8_t> report{10,123,0,0,0,0,0,0,0,10,0,0,0,0,0,0,0,0,0};
    assert(BuildTaskReply(*completion, request, report.data(), report.size(), 124, reply));
    const std::vector<std::uint8_t> expectedAck{
        21,0,0,0,1,10,124,0,0,0,0,0,0,0,8,0,0,0,0,3,4,8,0,0,0,0,0,0,0,0,0,0};
    assert(reply == expectedAck);
    report[10] = 1;
    assert(!BuildTaskReply(*completion, request, report.data(), report.size(), 124, reply));
    report[10] = 0;
    report[1] = 0;
    assert(!BuildTaskReply(*completion, request, report.data(), report.size(), 124, reply));
    assert(!BuildTaskReply(*completion, request, report.data(), 10, 124, reply));
    std::cout << "DCQoS wire contract and malformed-request tests passed\n";
}
