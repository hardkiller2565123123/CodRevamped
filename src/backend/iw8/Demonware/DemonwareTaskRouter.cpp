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
#include "Services/RestBootstrap.cpp"
#include "Services/LegacyBootstrap.cpp"
#include "Services/PublisherVariables.cpp"
#include "Internal/JsonObjectStoreParsing.cpp"
#include "Services/ObjectStore.cpp"
#include "Services/Achievements.cpp"
#include "Public/TaskRouter.cpp"
