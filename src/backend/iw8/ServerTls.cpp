#include "Server.h"
#include "Log.h"
#include "Protocol.h"
#include "Bgs/BgsDispatcher.h"
#include "Web/WebAuthService.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define SECURITY_WIN32
#include <Windows.h>
#include <TlHelp32.h>
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <utility>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Bcrypt.lib")

#include "Tls/Transport/SocketIo.cpp"
#include "Tls/Trust/StockBundleDiscovery.cpp"
#include "Tls/Handshake/ClientHello.cpp"
#include "Tls/TlsSessionState.cpp"
#include "Tls/Trust/TrustManifest.cpp"
#include "Tls/Trust/BundleSigner.cpp"
#include "Tls/Trust/BundleJson.cpp"
#include "Bgs/Diagnostics/PlaintextIntrospection.cpp"
#include "Tls/Certificates/RevocationArtifacts.cpp"
#include "Tls/Certificates/LeafCertificate.cpp"
#include "Tls/Certificates/CertificateAuthority.cpp"
#include "Tls/Credentials/CredentialPolicy.cpp"
#include "Tls/Transport/TlsRecordIo.cpp"
#include "Bgs/Auth/ExternalChallenge.cpp"
#include "Tls/WebSocket/WebSocketProtocol.cpp"
#include "Bgs/Transport/BgsPlaintext.cpp"
#include "Web/TlsWebRequest.cpp"
#include "Tls/Transport/TlsEngine.cpp"
#include "Server/Lifecycle/Start.cpp"
#include "Server/Networking/TcpReceive.cpp"
#include "Server/Lifecycle/CloseClient.cpp"
#include "Server/Lifecycle/Run.cpp"
#include "Server/Lifecycle/Stop.cpp"
