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

#define BuildDwBnetAuthResponse BuildDwBnetAuthResponse_UnpatchedIdentity
#include "Internal/AuthResponseBuilders.cpp"
#undef BuildDwBnetAuthResponse
#include "Internal/AuthIdentityPatch.cpp"

#include "Public/InitializeSigner.cpp"

#define TryHandleLocalWebRequest TryHandleLocalWebRequest_BaseUmbrellaIdentity
#include "Public/HttpRouter.cpp"
#undef TryHandleLocalWebRequest

#define TryHandleLocalWebRequest TryHandleLocalWebRequest_PreUpdateBootstrap
#include "Public/HttpRouterUmbrellaIdentityFix.cpp"
#undef TryHandleLocalWebRequest
#include "Public/HttpRouterUpdateBootstrapFix.cpp"

#include "Public/PostLsgDiagnostics.cpp"
#include "Internal/LsgKeyDecoding.cpp"
#include "Public/LsgKeyMaterial.cpp"
#include "Public/PipelinePolling.cpp"

// haha you really thought there would be code in here na just some #includes.
//go check somewhere else. ha NERD
