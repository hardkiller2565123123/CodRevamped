#pragma once

#pragma section(".crcomp$a", read)
#pragma section(".crcomp$m", read)
#pragma section(".crcomp$z", read)

#include "component_interface.hpp"

class component_loader final
{
public:
	using component_factory = std::unique_ptr<component_interface>(*)();

	class premature_shutdown_trigger final : public std::exception
	{
		[[nodiscard]] const char* what() const noexcept override
		{
			return "Premature shutdown requested";
		}
	};

	template <typename T>
	static T* get()
	{
		for (const auto& component_ : get_components())
		{
			if (typeid(*component_.get()) == typeid(T))
			{
				return reinterpret_cast<T*>(component_.get());
			}
		}

		return nullptr;
	}

	static void register_component(std::unique_ptr<component_interface>&& component);
	static void instantiate_registered_components();

	static bool pre_start();
	static void post_unpack();
	static void pre_destroy();
	static void clean();

	static void trigger_premature_shutdown();

private:
	static std::vector<std::unique_ptr<component_interface>>& get_components();
};

#define CR_COMPONENT_JOIN2(a, b) a##b
#define CR_COMPONENT_JOIN(a, b) CR_COMPONENT_JOIN2(a, b)
#define CR_REGISTER_COMPONENT_IMPL(name, line)                                  \
namespace                                                                       \
{                                                                               \
    std::unique_ptr<component_interface> CR_COMPONENT_JOIN(cr_make_component_, line)() \
    {                                                                           \
        return std::make_unique<name>();                                        \
    }                                                                           \
    __declspec(allocate(".crcomp$m")) component_loader::component_factory const \
        CR_COMPONENT_JOIN(cr_component_factory_, line) =                        \
            &CR_COMPONENT_JOIN(cr_make_component_, line);                       \
}
#define REGISTER_COMPONENT(name) CR_REGISTER_COMPONENT_IMPL(name, __LINE__)
