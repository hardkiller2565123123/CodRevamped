#include "../../src/backend/iw8/Demonware/DemonwareTaskRouter.cpp"
#include <cassert>
#include <iostream>

static bool retail = true;
namespace revamped::iw8::web {
    bool UsesNativeSteamLoginKey() { return retail; }
    std::uint64_t GetCurrentLocalUserId() { return 123; }
}

int main()
{
    using namespace revamped::iw8::demonware;
    assert(RestPublisherContentSha1Base64("abc") == "qZk+NkcGgWq6PiVxeFDCbJzQ2J0=");
    const std::string publisherRequest =
        "client=iw-cod-iw8-steam&context=5800&extra=contentURL DW-Objectstore-ObjectIDs "
        "[{\"name\":\"store_v2.json\",\"owner\":\"raven\"},"
        "{\"name\":\"1_manifest_patch_pc_8.69.txt\",\"owner\":\"raven\"},"
        "{\"name\":\"missing-test-object\",\"owner\":\"raven\"}]";
    const auto metadata = BuildRestPublisherMetadataBody(
        reinterpret_cast<const std::uint8_t*>(publisherRequest.data()), publisherRequest.size());
    assert(metadata.find("\"contentLength\":17") != std::string::npos);
    assert(metadata.find(RestPublisherContentSha1Base64(
        revamped::iw8::localpublisher::RetailStoreBody())) != std::string::npos);
    assert(metadata.find("\"requestIndex\":2") != std::string::npos);
    assert(metadata.find("Error:ClientError:NotFound") != std::string::npos);
    assert(metadata.find("\"context\":\"5800\"") != std::string::npos);
    assert(metadata.find(RestPublisherContentSha1Base64(
        revamped::iw8::localpublisher::ManifestBodyForName(
            "1_manifest_patch_pc_8.69.txt"))) != std::string::npos);
    std::cout << "METADATA_JSON=" << metadata << '\n';
    auto profile = RestBootstrapBody(RestBootstrapKind::UsersStructuredDataGet, nullptr, 0);
    assert(profile.find("\"items\":[{\"payload\":\"ey") != std::string::npos);
    assert(profile.find("\"errorCode\":0") != std::string::npos);
    assert(profile.find("\"userID\":123") != std::string::npos);
    std::cout << "PROFILE_JSON=" << profile << '\n';
    retail = false;
    auto legacy = RestBootstrapBody(RestBootstrapKind::UsersStructuredDataGet, nullptr, 0);
    assert(legacy.find("\"structuredData\":{") != std::string::npos);
    assert(legacy.find("\"items\"") == std::string::npos);

    const auto* route = FindTaskRoute(80, 245);
    assert(route);
    TaskRequest request{};
    request.valid = true;
    request.serviceId = 80;
    request.taskId = 245;
    std::vector<std::uint8_t> bytes{0x17,8,8,0,0,0,10,4,'6','0','0','0',16,16,0};
    std::vector<std::uint8_t> reply;
    assert(!BuildTaskReply(*route, request, bytes.data(), bytes.size(), 2, reply));
    retail = true;
    assert(BuildTaskReply(*route, request, bytes.data(), bytes.size(), 2, reply));
    assert(!BuildTaskReply(*route, request, bytes.data(), bytes.size()-2, 2, reply));
    bytes[13] = 17;
    assert(!BuildTaskReply(*route, request, bytes.data(), bytes.size(), 2, reply));
    bytes[13] = 0;
    assert(!BuildTaskReply(*route, request, bytes.data(), bytes.size(), 2, reply));
    bytes[13] = 16;
    bytes[8] = '9';
    assert(!BuildTaskReply(*route, request, bytes.data(), bytes.size(), 2, reply));
    bytes[8] = '5'; bytes[9] = '8';
    retail = false;
    assert(BuildTaskReply(*route, request, bytes.data(), bytes.size(), 2, reply));
    assert(revamped::iw8::localpublisher::RetailStoreBody() == "{\"categories\":[]}");
    std::cout << "PASS retail/legacy profile and balances; malformed bounds rejected\n";
}
