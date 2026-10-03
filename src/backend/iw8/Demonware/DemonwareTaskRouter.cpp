#include "DemonwareTaskRouter.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>

#include "Internal/Serialization.cpp"
#include "Internal/SemanticProtocol.cpp"
#include "Services/RestBootstrap.cpp"
#include "Services/LegacyBootstrap.cpp"
#include "Services/PublisherVariables.cpp"
#include "Internal/JsonObjectStoreParsing.cpp"
#include "Services/ObjectStore.cpp"
#include "Services/PublisherObjectStore.cpp"
#include "Services/Achievements.cpp"

// Preserve the existing router as the fallback implementation. The wrapper adds
// only the now-proven IW8 publisher ObjectStore tasks (0xC1/8 and 0xC1/16).
#define FindTaskRoute FindTaskRoute_Base
#define DescribeTaskRequest DescribeTaskRequest_Base
#define BuildTaskReply BuildTaskReply_Base
#include "Public/TaskRouter.cpp"
#undef BuildTaskReply
#undef DescribeTaskRequest
#undef FindTaskRoute

#include "Public/TaskRouterOverrides.cpp"
