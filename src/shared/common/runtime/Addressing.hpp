#pragma once

#include <cstddef>
#include <cstdint>

namespace codrevamped::address
{
	inline constexpr std::uintptr_t preferred_image_base = 0x140000000ull;

	// Optional per-game preferred-address translator. Normally _g uses the
	// standard preferred-image-base delta. T8 installs this callback so the
	// same Retail BO4 source can translate preferred VAs through the active
	// Retail / MP Beta / Blackout Beta profile table. Other clients keep the
	// normal translation because they never install a callback.
	using preferred_resolver_t = std::uintptr_t(*)(std::uintptr_t preferred_address) noexcept;
	void set_preferred_resolver(preferred_resolver_t resolver) noexcept;
	void clear_preferred_resolver() noexcept;

	std::uintptr_t base();
	std::uintptr_t from_rva(std::uintptr_t rva);
	std::uintptr_t from_preferred(std::uintptr_t address);
	std::uintptr_t to_rva(std::uintptr_t address);
	std::uintptr_t to_preferred(std::uintptr_t address);
}

size_t operator"" _b(size_t val);
size_t operator"" _g(size_t val);
size_t reverse_b(size_t val);
size_t reverse_b(const void* val);
size_t reverse_g(size_t val);
size_t reverse_g(const void* val);
