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
#include "Internal/AuthResponseBuilders.cpp"
#include "Public/InitializeSigner.cpp"
#include "Public/HttpRouter.cpp"
#include "Public/PostLsgDiagnostics.cpp"
#include "Internal/LsgKeyDecoding.cpp"
#include "Public/LsgKeyMaterial.cpp"
#include "Public/PipelinePolling.cpp"

// haha you really thought there would be code in here na just some #includes.
//go check somewhere else. ha NERD
