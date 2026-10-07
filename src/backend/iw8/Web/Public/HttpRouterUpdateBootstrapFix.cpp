namespace revamped::iw8::web
{
    namespace
    {
        constexpr const char* kWarzoneStoreLayoutJson = "{\"categories\":[]}";

        bool EndsWithUpdateBootstrap(const std::string& value, const char* suffix)
        {
            if (!suffix)
                return false;

            const std::size_t suffixLength = std::strlen(suffix);
            return value.size() >= suffixLength &&
                value.compare(value.size() - suffixLength, suffixLength, suffix) == 0;
        }

        bool ParseUpdateBootstrapRequest(
            const std::vector<std::uint8_t>& buffer,
            std::string& method,
            std::string& host,
            std::string& path,
            std::size_t& totalBytes)
        {
            method.clear();
            host.clear();
            path.clear();
            totalBytes = 0;

            if (buffer.empty())
                return false;

            const std::string all(
                reinterpret_cast<const char*>(buffer.data()), buffer.size());

            const std::size_t headerEndMarker = all.find("\r\n\r\n");
            if (headerEndMarker == std::string::npos)
                return false;

            const std::size_t headerBytes = headerEndMarker + 4u;
            const std::string headers = all.substr(0, headerEndMarker + 2u);

            std::size_t contentLength = 0;
            const std::string contentLengthText =
                HeaderValue(headers, "Content-Length");

            if (!contentLengthText.empty())
            {
                char* end = nullptr;
                const unsigned long long parsed =
                    std::strtoull(contentLengthText.c_str(), &end, 10);

                if (!end || end == contentLengthText.c_str() || *end != '\0' ||
                    parsed > 1024ull * 1024ull)
                {
                    return false;
                }

                contentLength = static_cast<std::size_t>(parsed);
            }

            totalBytes = headerBytes + contentLength;
            if (buffer.size() < totalBytes)
                return false;

            const std::size_t firstLineEnd = headers.find("\r\n");
            if (firstLineEnd == std::string::npos)
                return false;

            const std::string requestLine = headers.substr(0, firstLineEnd);
            const std::size_t firstSpace = requestLine.find(' ');
            const std::size_t secondSpace =
                firstSpace == std::string::npos
                    ? std::string::npos
                    : requestLine.find(' ', firstSpace + 1u);

            if (firstSpace == std::string::npos ||
                secondSpace == std::string::npos)
            {
                return false;
            }

            method = requestLine.substr(0, firstSpace);
            std::string target =
                requestLine.substr(firstSpace + 1u, secondSpace - firstSpace - 1u);

            host = HeaderValue(headers, "Host");

            const std::string targetLower = Lower(target);
            if (targetLower.rfind("https://", 0) == 0 ||
                targetLower.rfind("http://", 0) == 0)
            {
                const std::size_t authorityStart = target.find("//") + 2u;
                const std::size_t pathStart = target.find('/', authorityStart);

                if (host.empty())
                {
                    host = target.substr(
                        authorityStart,
                        pathStart == std::string::npos
                            ? std::string::npos
                            : pathStart - authorityStart);
                }

                target =
                    pathStart == std::string::npos ? "/" : target.substr(pathStart);
            }

            const std::size_t question = target.find('?');
            path = target.substr(0, question);
            return true;
        }
    }

    HttpResult TryHandleLocalWebRequest(std::vector<std::uint8_t>& buffer)
    {
        std::string method;
        std::string host;
        std::string path;
        std::size_t totalBytes = 0;

        if (!ParseUpdateBootstrapRequest(
                buffer, method, host, path, totalBytes))
        {
            return TryHandleLocalWebRequest_PreUpdateBootstrap(buffer);
        }

        const std::string hostLower = Lower(host);
        const std::string pathLower = Lower(path);

        const bool objectStoreHost =
            hostLower == "objectstore.prod.demonware.net" ||
            EndsWithUpdateBootstrap(hostLower, ".objectstore.prod.demonware.net");

        const bool warzoneStoreLayout =
            method == "GET" &&
            objectStoreHost &&
            EndsWithUpdateBootstrap(pathLower, "/store_v2_warzone.json") &&
            pathLower.find("/__revamped/objectstore/publisher/") == 0;

        const bool metrics =
            method == "POST" &&
            hostLower.find("demonware.net") != std::string::npos &&
            pathLower.rfind("/v1.0/secureingest/", 0) == 0 &&
            EndsWithUpdateBootstrap(pathLower, "/metrics/");

        if (!warzoneStoreLayout && !metrics)
            return TryHandleLocalWebRequest_PreUpdateBootstrap(buffer);

        HttpResult result{};
        result.complete = true;
        result.handled = true;
        result.method = method;
        result.host = host;
        result.path = path;
        result.requestBytes = totalBytes;

        if (warzoneStoreLayout)
        {
            const std::string body = kWarzoneStoreLayoutJson;

            result.statusCode = 200;
            result.label = "local ObjectStore publisher store_v2_warzone.json";
            result.response = BuildResponse(
                200, "OK", "application/json; charset=utf-8", body);

            log::Print(
                "[DW-OBJECTSTORE-HTTP] host=%s path=%s status=200 bytes=%llu "
                "body=local-publisher-json compatibility=warzone-store-layout",
                host.c_str(),
                path.c_str(),
                static_cast<unsigned long long>(body.size()));
        }
        else
        {
            result.statusCode = 204;
            result.label = "local Demonware metrics accepted";
            result.response =
                "HTTP/1.1 204 No Content\r\n"
                "Content-Length: 0\r\n"
                "Cache-Control: no-store\r\n"
                "Connection: keep-alive\r\n"
                "\r\n";

            log::Print(
                "[DW-METRICS-HTTP] host=%s path=%s status=204 "
                "body=discarded-local-metrics",
                host.c_str(),
                path.c_str());
        }

        buffer.erase(
            buffer.begin(),
            buffer.begin() + static_cast<std::ptrdiff_t>(totalBytes));

        return result;
    }
}
