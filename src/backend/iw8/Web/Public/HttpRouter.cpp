#include "HttpRouter.h"

namespace revamped::iw8::web
{
    HttpResult TryHandleLocalWebRequest(std::vector<std::uint8_t>& buffer)
    {
        HttpResult result{};
        if (buffer.empty()) return result;

        const std::string all(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        const std::size_t headerEndMarker = all.find("\r\n\r\n");
        if (headerEndMarker == std::string::npos)
            return result;

        const std::size_t headerBytes = headerEndMarker + 4;
        const std::string headers = all.substr(0, headerEndMarker + 2);
        const std::string contentLengthText = HeaderValue(headers, "Content-Length");
        std::size_t contentLength = 0;
        if (!contentLengthText.empty())
        {
            char* end = nullptr;
            const unsigned long long parsed = std::strtoull(contentLengthText.c_str(), &end, 10);
            if (!end || end == contentLengthText.c_str() || *end != '\0' || parsed > 1024ull * 1024ull)
            {
                result.complete = true;
                result.handled = false;
                result.statusCode = 400;
                result.label = "invalid Content-Length";
                result.response = BuildResponse(400, "Bad Request", "application/json", "{\"error\":\"bad_request\"}");
                buffer.clear();
                return result;
            }
            contentLength = static_cast<std::size_t>(parsed);
        }

        const std::size_t totalBytes = headerBytes + contentLength;
        if (buffer.size() < totalBytes)
            return result;

        result.complete = true;
        result.requestBytes = totalBytes;

        const std::size_t firstLineEnd = headers.find("\r\n");
        if (firstLineEnd == std::string::npos)
        {
            result.statusCode = 400;
            result.label = "malformed request line";
            result.response = BuildResponse(400, "Bad Request", "application/json", "{\"error\":\"bad_request\"}");
            buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(totalBytes));
            return result;
        }

        const std::string requestLine = headers.substr(0, firstLineEnd);
        const std::size_t firstSpace = requestLine.find(' ');
        const std::size_t secondSpace = firstSpace == std::string::npos ? std::string::npos : requestLine.find(' ', firstSpace + 1);
        if (firstSpace == std::string::npos || secondSpace == std::string::npos)
        {
            result.statusCode = 400;
            result.label = "malformed request line";
            result.response = BuildResponse(400, "Bad Request", "application/json", "{\"error\":\"bad_request\"}");
            buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(totalBytes));
            return result;
        }

        result.method = requestLine.substr(0, firstSpace);
        std::string target = requestLine.substr(firstSpace + 1, secondSpace - firstSpace - 1);
        result.host = HeaderValue(headers, "Host");
        // Be tolerant of absolute-form HTTP request targets as well as normal
        // origin-form paths; redirected clients can use either.
        const std::string targetLower = Lower(target);
        if (targetLower.rfind("https://", 0) == 0 || targetLower.rfind("http://", 0) == 0)
        {
            const std::size_t authorityStart = target.find("//") + 2;
            const std::size_t pathStart = target.find('/', authorityStart);
            if (result.host.empty())
                result.host = target.substr(authorityStart, pathStart == std::string::npos ? std::string::npos : pathStart - authorityStart);
            target = pathStart == std::string::npos ? "/" : target.substr(pathStart);
        }
        const std::size_t question = target.find('?');
        result.path = target.substr(0, question);
        const std::string hostLower = Lower(result.host);
        const std::string pathLower = Lower(result.path);
        const std::string query = question == std::string::npos ? std::string{} : target.substr(question + 1);
        const std::string body = contentLength ? all.substr(headerBytes, contentLength) : std::string{};

        const std::string contentTypeLower = Lower(HeaderValue(headers, "Content-Type"));
        const bool bodyIsJson = contentTypeLower.find("application/json") != std::string::npos || LooksLikeJsonObject(body);
        const bool bodyIsForm = !bodyIsJson &&
            (contentTypeLower.find("application/x-www-form-urlencoded") != std::string::npos || body.find('=') != std::string::npos);
        const std::string queryKeys = FieldKeys(query);
        const std::string bodyKeys = bodyIsJson ? JsonTopLevelKeys(body) : (bodyIsForm ? FieldKeys(body) : std::string{});
        if (!queryKeys.empty() && !bodyKeys.empty()) result.formKeys = queryKeys + "," + bodyKeys;
        else result.formKeys = !queryKeys.empty() ? queryKeys : bodyKeys;

        // MW2019 obtains a short-lived OAuth access token immediately after
        // AuthenticationService.GenerateWebCredentials.  Accept only the local
        // synthetic client_sso shape; no Blizzard username/password is accepted.
        const bool oauthHost = hostLower.find("oauth-") == 0 || hostLower.find("battle.net") != std::string::npos;
        const bool oauthPath = pathLower == "/oauth" || pathLower.find("/oauth/") == 0;
        const bool clientSso = HasFormPair(query, "grant_type", "client_sso") ||
            HasFormPair(body, "grant_type", "client_sso");
        if ((oauthPath || oauthHost) && clientSso)
        {
            const std::string responseBody =
                "{\"access_token\":\"revamped-iw8-local-access-token\","
                "\"token_type\":\"bearer\",\"expires_in\":86400,"
                "\"scope\":\"account.standard\"}";
            result.handled = true;
            result.statusCode = 200;
            result.label = "local OAuth client_sso access token";
            result.response = BuildResponse(200, "OK", "application/json; charset=utf-8", responseBody);
        }
        else if (result.method == "POST" &&
            hostLower == "prod.umbrella.demonware.net" &&
            pathLower == "/v1.0/tokens/lsg/")
        {
            // Stock IW8 reaches this exchange only after the signed Auth3 response
            // has been accepted far enough to request an LSG token.  Keep this
            // server-driven: validate the captured request shape and issue a local
            // deterministic token; no client login/fence state is modified.
            // IW8 1.44 sends these values on the URL query for this POST.  The
            // generic request logger intentionally reports query + body keys as
            // one formKeys list, so validate both sources here as well.  Other
            // builds may choose a normal urlencoded body, so keep that accepted.
            const bool queryHasClient = HasFormKey(query, "client");
            const bool queryHasTicket = HasFormKey(query, "ticket");
            const bool queryHasIvSeed = HasFormKey(query, "initialVectorSeed");
            const bool queryHasTitleId = HasFormKey(query, "titleID");
            const bool formHasClient = bodyIsForm && HasFormKey(body, "client");
            const bool formHasTicket = bodyIsForm && HasFormKey(body, "ticket");
            const bool formHasIvSeed = bodyIsForm && HasFormKey(body, "initialVectorSeed");
            const bool formHasTitleId = bodyIsForm && HasFormKey(body, "titleID");

            // IW8 1.44 actually splits this POST across sources: `client` is
            // carried by the URL query while the ticket/IV/title fields are a
            // JSON object in the request body.  The generic formKeys logger has
            // always merged query keys with JSON top-level keys, which is why it
            // could see all four while the v15 endpoint validator only saw
            // `client`.  Use the same accepted sources here so diagnostics and
            // endpoint validation cannot disagree again.
            const bool jsonHasClient = bodyIsJson && JsonValueType(body, "client") != '-';
            const bool jsonHasTicket = bodyIsJson && JsonValueType(body, "ticket") != '-';
            const bool jsonHasIvSeed = bodyIsJson && JsonValueType(body, "initialVectorSeed") != '-';
            const bool jsonHasTitleId = bodyIsJson && JsonValueType(body, "titleID") != '-';

            const bool hasClient = queryHasClient || formHasClient || jsonHasClient;
            const bool hasTicket = queryHasTicket || formHasTicket || jsonHasTicket;
            const bool hasIvSeed = queryHasIvSeed || formHasIvSeed || jsonHasIvSeed;
            const bool hasTitleId = queryHasTitleId || formHasTitleId || jsonHasTitleId;

            const char* bodyStyle = bodyIsJson ? "json" : (bodyIsForm ? "form" : "none");
            const char* fieldSource = !query.empty() && bodyIsJson ? "query+json" :
                (!query.empty() && bodyIsForm ? "query+form" :
                (!query.empty() ? "query" : (bodyIsJson ? "json" : (bodyIsForm ? "form" : "none"))));
            std::ostringstream detail;
            detail << "local Demonware Umbrella LSG token exchange"
                   << " fieldSource=" << fieldSource
                   << " bodyStyle=" << bodyStyle
                   << " client=" << (hasClient ? "present" : "missing")
                   << " ticket=" << (hasTicket ? "present" : "missing")
                   << " initialVectorSeed=" << (hasIvSeed ? "present" : "missing")
                   << " titleID=" << (hasTitleId ? "present" : "missing")
                   << " values=REDACTED responseStyle=UMBRELLA_STOCK_NAMED_V15 stateWrites=off";

            result.handled = true;
            if (!hasClient || !hasTicket || !hasIvSeed || !hasTitleId)
            {
                result.statusCode = 400;
                result.label = detail.str();
                AppendAuthPipelineV58("UMBRELLA_REJECT shape client=%s ticket=%s iv=%s title=%s source=%s",
                    hasClient ? "present" : "missing", hasTicket ? "present" : "missing",
                    hasIvSeed ? "present" : "missing", hasTitleId ? "present" : "missing", fieldSource);
                result.response = BuildResponse(400, "Bad Request",
                    "application/json; charset=utf-8",
                    "{\"error\":\"revamped_bad_umbrella_lsg_shape\"}");
            }
            else
            {
                // The stock 1.44 request carries its Umbrella `ticket` as a JSON
                // string. Returning a made-up printable token proved insufficient.
                // The stock request itself is useful here as the Auth3 credential
                // presented to Umbrella; V67 mints a separate structured LSG token
                // below instead of echoing this request credential back to the client.
                std::string requestTicket;
                const char ticketValueType = bodyIsJson ? JsonValueType(body, "ticket") : '-';
                bool requestTicketExtracted = false;
                if (bodyIsJson && ticketValueType == 's')
                    requestTicketExtracted = JsonStringValue(body, "ticket", requestTicket);
                else if (bodyIsJson && ticketValueType != '-')
                    requestTicketExtracted = JsonUnsignedText(body, "ticket", requestTicket);

                // V72: IW8 1.44 carries initialVectorSeed in the JSON body on the
                // proven path.  Preserve its exact textual representation without
                // logging it so the LSG oracle can test raw/base64/hex 24-byte
                // interpretations alongside the ticket-carried session keys.
                std::string umbrellaInitialVectorSeed;
                if (bodyIsJson)
                {
                    const char ivType = JsonValueType(body, "initialVectorSeed");
                    if (ivType == 's')
                        JsonStringValue(body, "initialVectorSeed", umbrellaInitialVectorSeed);
                    else if (ivType != '-')
                        JsonUnsignedText(body, "initialVectorSeed", umbrellaInitialVectorSeed);
                }
                g_authPipeline.lastUmbrellaInitialVectorSeed = umbrellaInitialVectorSeed;

                const Auth3TicketMatch ticketMatch = CorrelateUmbrellaTicket(requestTicket);

                // V67: the request's Auth3 server_ticket is the credential used
                // to authorize this exchange, but it is not the credential we
                // return to bdLobby.  V61 proved the host-only endpoint reaches
                // native LSG; V66 then proved the echoed server_ticket has no DW
                // ticket magic/session key at the packed ticket offsets.  Mint a
                // structured LSG ticket tied to the same Auth3 session key.
                const bool requestServerTicketVerified =
                    requestTicketExtracted &&
                    !requestTicket.empty() &&
                    ticketMatch.exactServerMatch;
                const std::uint32_t lsgTitleId = ticketMatch.titleId != 0u
                    ? ticketMatch.titleId
                    : 5800u;
                std::string localLsgToken = BuildLocalLsgTokenV67(lsgTitleId);
                if (localLsgToken.empty() && ticketMatch.haveAuth3ClientTicket)
                    localLsgToken = g_authPipeline.lastAuth3ClientTicket;
                g_authPipeline.lastMintedLsgToken = localLsgToken;

                const UmbrellaTicketShape ticketShape = DescribeUmbrellaTicket(requestTicket);
                const UmbrellaTicketShape responseTicketShape = DescribeUmbrellaTicket(localLsgToken);
                const std::string requestTicketHash = Sha256Prefix(requestTicket);
                const std::string auth3ClientHash = Sha256Prefix(g_authPipeline.lastAuth3ClientTicket);
                const std::string auth3ServerHash = Sha256Prefix(g_authPipeline.lastAuth3ServerTicket);
                AppendAuthPipelineV58("UMBRELLA_REQUEST auth3Serial=%llu ageMs=%llu ticketType=%c ticketLen=%llu requestHash=%s auth3ClientHash=%s auth3ServerHash=%s exactClient=%s exactServer=%s decodedBytes=%llu dwAuthMagic=%s titleId=%u values=REDACTED",
                    static_cast<unsigned long long>(ticketMatch.serial), static_cast<unsigned long long>(ticketMatch.ageMs),
                    ticketValueType, static_cast<unsigned long long>(requestTicket.size()), requestTicketHash.c_str(),
                    auth3ClientHash.c_str(), auth3ServerHash.c_str(), ticketMatch.exactClientMatch ? "YES" : "NO",
                    ticketMatch.exactServerMatch ? "YES" : "NO", static_cast<unsigned long long>(ticketShape.decodedBytes),
                    ticketShape.dwAuthTicketMagic ? "YES" : "NO", static_cast<unsigned>(ticketShape.titleId));

                detail << " ticketType=" << ticketValueType
                       << " ticketLen=" << requestTicket.size()
                       << " tokenSource="
                       << (!localLsgToken.empty() ? "mintedDwAuthTicketV67" : "fallback")
                       << " auth3Serial=" << ticketMatch.serial
                       << " auth3AgeMs=" << static_cast<unsigned long long>(ticketMatch.ageMs)
                       << " ticketMatchesAuth3Client=" << (ticketMatch.exactClientMatch ? "YES" : "NO")
                       << " ticketMatchesAuth3Server=" << (ticketMatch.exactServerMatch ? "YES" : "NO")
                       << " auth3ClientPresent=" << (ticketMatch.haveAuth3ClientTicket ? "yes" : "no")
                       << " auth3ServerPresent=" << (ticketMatch.haveAuth3ServerTicket ? "yes" : "no")
                       << " responseStyle=UMBRELLA_STOCK_NAMED_V15";

                log::Print("[LSG-TICKET-CORRELATION] auth3Serial=%llu requestHash=%s auth3ClientHash=%s auth3ServerHash=%s exactClient=%s exactServer=%s base64=%s decodedBytes=%llu dwAuthMagic=%s type=%u titleId=%u issued=%u expires=%u sessionKeyNonZero=%u values=REDACTED stateWrites=off",
                    static_cast<unsigned long long>(ticketMatch.serial),
                    requestTicketHash.c_str(), auth3ClientHash.c_str(), auth3ServerHash.c_str(),
                    ticketMatch.exactClientMatch ? "YES" : "NO",
                    ticketMatch.exactServerMatch ? "YES" : "NO",
                    ticketShape.base64Ok ? "yes" : "no",
                    static_cast<unsigned long long>(ticketShape.decodedBytes),
                    ticketShape.dwAuthTicketMagic ? "YES" : "NO",
                    static_cast<unsigned>(ticketShape.type),
                    static_cast<unsigned>(ticketShape.titleId),
                    static_cast<unsigned>(ticketShape.timeIssued),
                    static_cast<unsigned>(ticketShape.timeExpires),
                    ticketShape.sessionKeyNonZero);

                log::Print("[AUTH-V67] LSG_TOKEN_MINTED auth3Serial=%llu requestServerTicketVerified=%s rawBytes=%llu dwAuthMagic=%s type=%u titleId=%u issued=%u expires=%u sessionKeyNonZero=%u tokenHash=%s values=REDACTED stateWrites=off",
                    static_cast<unsigned long long>(ticketMatch.serial),
                    requestServerTicketVerified ? "YES" : "NO",
                    static_cast<unsigned long long>(responseTicketShape.decodedBytes),
                    responseTicketShape.dwAuthTicketMagic ? "YES" : "NO",
                    static_cast<unsigned>(responseTicketShape.type),
                    static_cast<unsigned>(responseTicketShape.titleId),
                    static_cast<unsigned>(responseTicketShape.timeIssued),
                    static_cast<unsigned>(responseTicketShape.timeExpires),
                    responseTicketShape.sessionKeyNonZero,
                    Sha256Prefix(localLsgToken).c_str());
                AppendAuthPipelineV58("AUTH_V67_LSG_TOKEN_MINTED auth3Serial=%llu requestServerTicketVerified=%s rawBytes=%llu dwAuthMagic=%s titleId=%u sessionKeyNonZero=%u tokenHash=%s next=expect_native_0x82",
                    static_cast<unsigned long long>(ticketMatch.serial),
                    requestServerTicketVerified ? "YES" : "NO",
                    static_cast<unsigned long long>(responseTicketShape.decodedBytes),
                    responseTicketShape.dwAuthTicketMagic ? "YES" : "NO",
                    static_cast<unsigned>(responseTicketShape.titleId),
                    responseTicketShape.sessionKeyNonZero,
                    Sha256Prefix(localLsgToken).c_str());

                // V15 keeps only field names that are actually present in the
                // stock 1.44 image: the proven legacy bdUmbrellaUserAccount names,
                // generic `token`, and camel-case `lsgEndpoint`.  V14 proved that
                // `expires_in` and snake-case `lsg_endpoint` are not present as exact
                // stock strings, so do not keep emitting those speculative names.
                // This remains a server-protocol compatibility probe only.
                //
                // Do not claim stock accepted this result until a lobby DNS/socket
                // transition is actually observed.
                // V61: V60 produced the first runtime LSG stream attempts, but the stock
                // client resolved the host:port string "127.0.0.1:3075" to the invalid
                // sentinel 0.255.0.255 and then used its own fixed TCP port 3074.  Test the
                // stock-shaped endpoint as a host/IP only while preserving every proven
                // stock field name. V67 keeps that endpoint fix and replaces only the
                // response token material. This changes only the
                // emulated server response; no client login/DW state is forced.
                const LONG responseOrdinal = InterlockedIncrement(&g_authPipeline.umbrellaSweepCount);
                const std::string responseToken = localLsgToken;
                const std::string localLobbyEndpoint = "127.0.0.1";
                const std::string responseBody =
                    "{\"umbrellaID\":1,\"accessToken\":\"" + JsonEscape(responseToken) +
                    "\",\"expires\":86400,\"accounts\":[],"
                    "\"token\":\"" + JsonEscape(responseToken) +
                    "\",\"lsgEndpoint\":\"" + JsonEscape(localLobbyEndpoint) + "\"}";
                result.statusCode = 200;
                result.label = detail.str();
                result.response = BuildResponse(200, "OK", "application/json; charset=utf-8", responseBody);
                MarkUmbrellaLsgAccepted(ticketMatch.serial);

                log::Print("[AUTH-V67] UMBRELLA_RESPONSE ordinal=%ld auth3Serial=%llu exactServer=%s schema=FULL_STOCK_NAMED tokenSource=%s tokenLen=%llu endpoint=%s endpointFormat=HOST_ONLY clientPortPolicy=FIXED_3074 deterministic=yes next=expect_TCP_LSG_HELLO",
                    static_cast<long>(responseOrdinal), static_cast<unsigned long long>(ticketMatch.serial),
                    ticketMatch.exactServerMatch ? "YES" : "NO",
                    "mintedDwAuthTicketV67",
                    static_cast<unsigned long long>(responseToken.size()), localLobbyEndpoint.c_str());
                AppendAuthPipelineV58("AUTH_V67_UMBRELLA_RESPONSE ordinal=%ld auth3Serial=%llu exactServer=%s schema=FULL_STOCK_NAMED tokenSource=%s tokenLen=%llu endpoint=%s endpointFormat=HOST_ONLY clientPortPolicy=FIXED_3074 deterministic=yes next=expect_TCP_LSG_HELLO",
                    static_cast<long>(responseOrdinal), static_cast<unsigned long long>(ticketMatch.serial),
                    ticketMatch.exactServerMatch ? "YES" : "NO",
                    "mintedDwAuthTicketV67",
                    static_cast<unsigned long long>(responseToken.size()), localLobbyEndpoint.c_str());
            }
        }
        else if (result.method == "POST" && pathLower == "/auth/" &&
            hostLower.find("demonware.net") != std::string::npos)
        {
            std::string authTask;
            std::string titleIdText;
            std::string ivSeed;
            std::string identity;
            std::string serviceLevel;
            std::string extraData;
            const std::string transactionId = HeaderValue(headers, "X-TransactionID");
            const std::string requestSignature = HeaderValue(headers, "X-Signature");
            const std::string acceptType = HeaderValue(headers, "Accept");
            const std::string userAgent = HeaderValue(headers, "User-Agent");
            const bool taskOk = bodyIsJson && JsonUnsignedText(body, "auth_task", authTask);
            const bool titleOk = bodyIsJson && JsonUnsignedText(body, "title_id", titleIdText);
            const bool ivOk = bodyIsJson && JsonUnsignedText(body, "iv_seed", ivSeed);
            const bool identityOk = bodyIsJson && JsonStringValue(body, "identity", identity);
            const bool serviceLevelOk = bodyIsJson && JsonStringValue(body, "service_level", serviceLevel);
            const bool extraDataOk = bodyIsJson && JsonStringValue(body, "extra_data", extraData) && LooksLikeJsonObject(extraData);

            std::string sessionToken;
            std::string accountToken;
            std::string machineId;
            std::string version;
            if (extraDataOk)
            {
                JsonStringValue(extraData, "session_token", sessionToken);
                JsonStringValue(extraData, "account_token", accountToken);
                JsonStringValue(extraData, "machine_id", machineId);
                JsonStringValue(extraData, "version", version);
            }

            const bool sessionTokenPrintableAscii = !sessionToken.empty() &&
                std::all_of(sessionToken.begin(), sessionToken.end(), [](const unsigned char c) {
                    return c >= 0x20u && c <= 0x7Eu;
                });
            const std::size_t sessionTokenControlBytes = static_cast<std::size_t>(
                std::count_if(sessionToken.begin(), sessionToken.end(), [](const unsigned char c) {
                    return c < 0x20u || c == 0x7Fu;
                }));

            std::uint32_t titleId = 0;
            if (titleOk)
            {
                const unsigned long parsed = std::strtoul(titleIdText.c_str(), nullptr, 10);
                titleId = static_cast<std::uint32_t>(parsed & 0xFFFFFFFFu);
            }

            std::ostringstream detail;
            detail << "IW8 Demonware BNet auth json=" << (bodyIsJson ? "yes" : "no")
                   << " task=" << (taskOk ? authTask : "?")
                   << " responseTask=" << (taskOk ? std::to_string(std::strtoul(authTask.c_str(), nullptr, 10) + 1u) : "?")
                   << " title=" << (titleOk ? titleIdText : "?")
                   << " ivSeed=" << (ivOk ? "present" : "missing")
                   << " identityLen=" << (identityOk ? identity.size() : 0u)
                   << " serviceLevel=" << (serviceLevelOk ? serviceLevel : "?")
                   << " extraDataJson=" << (extraDataOk ? "yes" : "no")
                   << " nestedKeys=" << (extraDataOk ? JsonTopLevelKeys(extraData) : "")
                   << " versionLen=" << version.size()
                   << " sessionTokenLen=" << sessionToken.size()
                   << " sessionTokenPrintableAscii=" << (sessionTokenPrintableAscii ? "yes" : "no")
                   << " sessionTokenControlBytes=" << sessionTokenControlBytes
                   << " accountTokenLen=" << accountToken.size()
                   << " machineIdLen=" << machineId.size()
                   << " transactionId=" << (transactionId.empty() ? "missing" : "present")
                   << " transactionIdLen=" << transactionId.size()
                   << " requestSignature=" << (requestSignature.empty() ? "missing" : "present")
                   << " requestSignatureLen=" << requestSignature.size()
                   << " accept=" << (acceptType.empty() ? "missing" : acceptType)
                   << " userAgentLen=" << userAgent.size()
                   << " ticketMode=BNET_RAW_128 responseStyle=TASK_PLUS_ONE clientIdOut=iw-cod-iw8-bnet serviceLevelOut=paid"
                   << " responseSignature=RSA_PSS_SHA256"
                   << " httpStyle=TornadoServer/4.5.3 stateWrites=off";

            if (!bodyIsJson || !taskOk || !titleOk || !ivOk || !extraDataOk || sessionToken.empty())
            {
                result.handled = true;
                result.statusCode = 400;
                result.label = detail.str();
                AppendAuthPipelineV58("AUTH3_REJECT task=%s title=%s iv=%s extraData=%s sessionTokenLen=%llu",
                    taskOk ? authTask.c_str() : "?", titleOk ? titleIdText.c_str() : "?", ivOk ? "present" : "missing",
                    extraDataOk ? "yes" : "no", static_cast<unsigned long long>(sessionToken.size()));
                result.response = BuildResponse(400, "Bad Request", "application/json; charset=utf-8",
                    "{\"auth_task\":\"85\",\"code\":\"701\",\"error\":\"revamped_bad_dw_bnet_auth_shape\"}");
            }
            else
            {
                result.handled = true;
                result.statusCode = 200;
                result.label = detail.str();
                result.response = BuildDwAuthResponse(
                    BuildDwBnetAuthResponse(authTask, ivSeed, titleId, identity, serviceLevel, sessionToken));
                AppendAuthPipelineV58("AUTH3_RESPONSE status=200 requestTask=%s responseTask=%lu titleId=%u clientId=iw-cod-iw8-bnet accountType=bnet serviceLevel=paid lsg_endpoint=null signed=RSA_PSS_SHA256",
                    authTask.c_str(), std::strtoul(authTask.c_str(), nullptr, 10) + 1u, static_cast<unsigned>(titleId));
            }
        }
        else if (pathLower == "/optinservice/v1/getaccountoptins")
        {
            // Empty local consent collection: structurally valid and intentionally
            // contains no synthetic marketing/account-consent choices.
            result.handled = true;
            result.statusCode = 200;
            result.label = "local empty account opt-ins";
            result.response = BuildResponse(200, "OK", "application/json; charset=utf-8", "{\"optInSelections\":[]}");
        }
        else
        {
            result.handled = false;
            result.statusCode = 404;
            result.label = "unimplemented local HTTPS endpoint";
            result.response = BuildResponse(404, "Not Found", "application/json; charset=utf-8", "{\"error\":\"revamped_unimplemented\"}");
        }

        buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(totalBytes));
        return result;
    }
}
