#pragma once

#include "nt.hpp"
#include <ShlObj.h>
#include <wrl/client.h>

template <typename T>
using CComPtr = Microsoft::WRL::ComPtr<T>;

namespace utils::com
{
	bool select_folder(std::string& out_folder, const std::string& title = "Select a Folder", const std::string& selected_folder = {});
	CComPtr<IProgressDialog> create_progress_dialog();
}
