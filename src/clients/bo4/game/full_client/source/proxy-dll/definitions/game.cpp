#include "../std_include.hpp"
#include "game.hpp"
#include "../../../../T8BuildProfile.h"

namespace game
{
	const char* Com_GetVersionString()
	{
		static std::string version_string{};

		if (version_string.empty()) {
			version_string = std::format("BlackOps4 {}", Com_GetBuildVersion());
		}

		return version_string.data();
	}

	void verify_game_version()
	{
		std::string verification;
		if (!t8_build::VerifyActive(verification))
		{
			throw std::runtime_error("Unsupported BlackOps4.exe profile: " + verification);
		}


#ifdef DEBUG
		logger::write(logger::LOG_TYPE_DEBUG, "[ SYSTEM ]: Verified T8 profile '%s'", t8_build::Key(t8_build::Active()));
#endif // DEBUG
	}

    scoped_critical_section::scoped_critical_section(int32_t s, scoped_critical_section_type type) : _s(0), _hasOwnership(false), _isScopedRelease(false), _next(nullptr)
    {
        game::ScopedCriticalSectionConstructor(this, s, type);
    }

    scoped_critical_section::~scoped_critical_section()
    {
        game::ScopedCriticalSectionDestructor(this);
    }
}