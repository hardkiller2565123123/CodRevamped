#pragma once
#include "crypto.h"
#include <memory>
#include <string>

namespace bandwidth
{
    struct Reply
    {
        crypto::Bytes data;
        std::string operation;
        std::string detail;
    };

    // One authenticated lobby owns one bounded UDP measurement at a time.
    // Replay's LSG task 18/1 is raw bytes, not a typed bdTaskParams service.
    class Session
    {
      public:
        Session();
        ~Session();
        Session(const Session &) = delete;
        Session &operator=(const Session &) = delete;
        Reply dispatch(std::span<const uint8_t> request);

      private:
        struct State;
        std::unique_ptr<State> state_;
        unsigned attempts_ = 0;
    };
} // namespace bandwidth
