#include "WebAuthService.h"
#include "Common/Logging/Log.h"

#include <Windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cstdarg>
#include <cstdio>
#include <sstream>
#include <string_view>

#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Ncrypt.lib")

#include "Internal/AuthPipelineState.cpp"
#include "Internal/HttpFormParsing.cpp"
#include "Internal/JsonParsing.cpp"
#include "Internal/EncodingCrypto.cpp"
#include "Internal/AuthSigner.cpp"

// Keep the original builder intact, but expose it under a private name so the
// local-preservation identity shim can repair the synthetic ticket before the
// stock IW8 client consumes it.
#define BuildDwBnetAuthResponse BuildDwBnetAuthResponse_UnpatchedIdentity
#include "Internal/AuthResponseBuilders.cpp"
#undef BuildDwBnetAuthResponse
#include "Internal/AuthIdentityPatch.cpp"

#include "Public/InitializeSigner.cpp"

// Keep the stock/local HTTP router intact, but expose it under a private name so
// the Umbrella crossplay response can be completed with the identity fields that
// stock IW8 copies into bdLoginResult/bdAuthInfo before the LSG connection.
#define TryHandleLocalWebRequest TryHandleLocalWebRequest_BaseUmbrellaIdentity
#include "Public/HttpRouter.cpp"
#undef TryHandleLocalWebRequest
#include "Public/HttpRouterUmbrellaIdentityFix.cpp"

#include "Public/PostLsgDiagnostics.cpp"
#include "Internal/LsgKeyDecoding.cpp"
#include "Public/LsgKeyMaterial.cpp"
#include "Public/PipelinePolling.cpp"

// haha you really thought there would be code in here na just some #includes.
//go check somewhere else. ha NERD
