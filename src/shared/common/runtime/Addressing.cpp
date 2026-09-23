#include "Addressing.hpp"
#include <Windows.h>
#include <cassert>
#include <atomic>

namespace codrevamped::address
{
	namespace
	{
		std::atomic<preferred_resolver_t> g_preferred_resolver{ nullptr };
	}

	void set_preferred_resolver(const preferred_resolver_t resolver) noexcept
	{
		g_preferred_resolver.store(resolver, std::memory_order_release);
	}

	void clear_preferred_resolver() noexcept
	{
		g_preferred_resolver.store(nullptr, std::memory_order_release);
	}

	std::uintptr_t base()
	{
		static const auto value = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
		assert(value && "Failed to resolve game module base");
		return value;
	}

	std::uintptr_t from_rva(const std::uintptr_t rva) { return base() + rva; }
	std::uintptr_t from_preferred(const std::uintptr_t address)
	{
		if (const auto resolver = g_preferred_resolver.load(std::memory_order_acquire))
			return resolver(address);

		return base() + (address - preferred_image_base);
	}
	std::uintptr_t to_rva(const std::uintptr_t address) { return address - base(); }
	std::uintptr_t to_preferred(const std::uintptr_t address) { return (address - base()) + preferred_image_base; }
}

size_t operator"" _b(const size_t val) { return codrevamped::address::from_rva(val); }
size_t operator"" _g(const size_t val) { return codrevamped::address::from_preferred(val); }
size_t reverse_b(const size_t val) { return codrevamped::address::to_rva(val); }
size_t reverse_b(const void* val) { return reverse_b(reinterpret_cast<size_t>(val)); }
size_t reverse_g(const size_t val) { return codrevamped::address::to_preferred(val); }
size_t reverse_g(const void* val) { return reverse_g(reinterpret_cast<size_t>(val)); }
