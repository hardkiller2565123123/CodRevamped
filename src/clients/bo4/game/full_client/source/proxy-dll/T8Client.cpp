#include <std_include.hpp>
#include "definitions/game.hpp"
#include "loader/component_loader.hpp"
#include "component/platform.hpp"
#include "../../../T8BuildProfile.h"

#include "../../../../../../shared/common/utils/io.hpp"
#include "../../../../../../shared/common/utils/nt.hpp"
#include "../../../../../../shared/common/utils/hook.hpp"
#include "../../../../../../shared/common/utils/string.hpp"
#include "../../../../../../shared/common/utils/finally.hpp"

namespace
{
	DECLSPEC_NORETURN void WINAPI exit_hook(const uint32_t code)
	{
		component_loader::pre_destroy();
		ExitProcess(code);
	}

	std::pair<void**, void*> patch_import(const std::string& lib, const std::string& func, void* function)
	{
		static const utils::nt::library game{};

		const auto game_entry = game.get_iat_entry(lib, func);
		if (!game_entry)
		{
			if (t8_build::IsRetail())
				throw std::runtime_error("Import '" + func + "' not found!");

			logger::write(logger::LOG_TYPE_INFO,
				"[ T8 PROFILE ]: optional beta IAT import missing: %s::%s", lib.c_str(), func.c_str());
			return { nullptr, nullptr };
		}

#ifdef DEBUG
		logger::write(logger::LOG_TYPE_DEBUG, "[ IAT-HOOKS ]: Diverted %s::%s from %p to %p", utils::string::to_upper(lib).c_str(), func.c_str(), game_entry, function);
#endif // DEBUG

		const auto original_import = game_entry;
		utils::hook::set(game_entry, function);
		return { game_entry, original_import };
	}

	INT WINAPI get_system_metrics(int nIndex)
	{
		static bool initialized = false;

		if (!initialized) {
			game::verify_game_version();

			if (t8_build::FullClientAddressMapComplete())
			{
				component_loader::post_unpack();
			}
			else
			{
				logger::write(logger::LOG_TYPE_INFO,
					"[ T8 PROFILE ]: %s uses retail pre_start/common components; post_unpack hooks are deferred until beta RVAs are mapped",
					t8_build::Key(t8_build::Active()));
			}

			initialized = true;
		}

		return GetSystemMetrics(nIndex);
	}

	void patch_imports()
	{
		patch_import("user32.dll", "GetSystemMetrics", get_system_metrics);

		auto* exitEntry = utils::nt::library{}.get_iat_entry("kernel32.dll", "ExitProcess");
		if (exitEntry)
		{
			utils::hook::set(exitEntry, exit_hook);
		}
		else if (t8_build::IsRetail())
		{
			throw std::runtime_error("Import 'ExitProcess' not found!");
		}
	}

	void remove_crash_file()
	{
		const utils::nt::library game{};
		const auto game_file = game.get_path();
		auto game_path = std::filesystem::path(game_file);
		game_path.replace_extension(".start");

		utils::io::remove_file(game_path.generic_string());
	}

	bool run()
	{
		srand(uint32_t(time(nullptr)) ^ ~(GetTickCount() * GetCurrentProcessId()));

		{
			auto premature_shutdown = true;
			const auto _ = utils::finally([&premature_shutdown]()
				{
					if (premature_shutdown)
					{
						component_loader::pre_destroy();
					}
				});

			try
			{
				patch_imports();
				remove_crash_file();

				if (!component_loader::pre_start())
				{
					return false;
				}

				premature_shutdown = false;
			}
			catch (std::exception& e)
			{
				MessageBoxA(nullptr, e.what(), "ERROR", MB_ICONERROR);
				return false;
			}
		}

		return true;
	}

	class patch
	{
	public:
		patch() = default;

		patch(void* source, void* target)
			: source_(source)
		{
			memcpy(this->data_, source, sizeof(this->data_));
			utils::hook::jump(this->source_, target, true, true);
		}

		~patch()
		{
			if (source_)
			{
				utils::hook::copy(this->source_, this->data_, sizeof(this->data_));
			}
		}

		patch(patch&& obj) noexcept
			: patch()
		{
			this->operator=(std::move(obj));
		}

		patch& operator=(patch&& obj) noexcept
		{
			if (this != &obj)
			{
				this->~patch();

				this->source_ = obj.source_;
				memcpy(this->data_, obj.data_, sizeof(this->data_));

				obj.source_ = nullptr;
			}

			return *this;
		}

	private:
		void* source_{ nullptr };
		uint8_t data_[15]{};
	};

	std::vector<patch> initialization_hooks{};

	uint8_t* get_entry_point()
	{
		const utils::nt::library game{};
		return game.get_ptr() + game.get_optional_header()->AddressOfEntryPoint;
	}

	std::vector<uint8_t*> get_tls_callbacks()
	{
		const utils::nt::library game{};
		const auto& entry = game.get_optional_header()->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
		if (!entry.VirtualAddress || !entry.Size)
		{
			return {};
		}

		const auto* tls_dir = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(game.get_ptr() + entry.VirtualAddress);
		auto* callback = reinterpret_cast<uint8_t**>(tls_dir->AddressOfCallBacks);

		std::vector<uint8_t*> addresses{};
		while (callback && *callback)
		{
			addresses.emplace_back(*callback);
			++callback;
		}

		return addresses;
	}

	int patch_main()
	{
		if (!run())
		{
			return 1;
		}

		initialization_hooks.clear();
		return reinterpret_cast<int(*)()>(get_entry_point())();
	}

	void nullsub()
	{
	}

	void patch_entry_point()
	{
		initialization_hooks.emplace_back(get_entry_point(), patch_main);

		for (auto* tls_callback : get_tls_callbacks())
		{
			initialization_hooks.emplace_back(tls_callback, nullsub);
		}
	}
}

extern "C" bool CodRevamped_T8Shield_EarlyAttach()
{
	patch_entry_point();
	return true;
}

extern "C" void CodRevamped_T8Shield_PreDestroy()
{
	component_loader::pre_destroy();
}


extern "C"
{
	__declspec(dllexport) DWORD XInputGetCapabilities(DWORD dwUserIndex, DWORD dwFlags, struct XINPUT_CAPABILITIES* pCapabilities)
	{
		static auto func = []
		{
			char dir[MAX_PATH]{ 0 };
			GetSystemDirectoryA(dir, sizeof(dir));

			const auto d3d12 = utils::nt::library::load(dir + "/XInput9_1_0.dll"s);
			return d3d12.get_proc<decltype(&XInputGetCapabilities)>("XInputGetCapabilities");
		}();

		return func(dwUserIndex, dwFlags, pCapabilities);
	}

	__declspec(dllexport) DWORD XInputSetState(DWORD dwUserIndex, struct XINPUT_VIBRATION* pVibration)
	{
		static auto func = []
		{
			char dir[MAX_PATH]{ 0 };
			GetSystemDirectoryA(dir, sizeof(dir));

			const auto d3d12 = utils::nt::library::load(dir + "/XInput9_1_0.dll"s);
			return d3d12.get_proc<decltype(&XInputSetState)>("XInputSetState");
		}();

		return func(dwUserIndex, pVibration);
	}

	__declspec(dllexport) DWORD XInputGetState(DWORD dwUserIndex, struct XINPUT_STATE* pState)
	{
		static auto func = []
		{
			char dir[MAX_PATH]{ 0 };
			GetSystemDirectoryA(dir, sizeof(dir));

			const auto d3d12 = utils::nt::library::load(dir + "/XInput9_1_0.dll"s);
			return d3d12.get_proc<decltype(&XInputGetState)>("XInputGetState");
		}();

		return func(dwUserIndex, pState);
	}
}

extern "C" void CodRevamped_T8Shield_SetUsername(const char* name)
{
	platform::set_revamped_username(name ? name : "Revampedplayer");
}
