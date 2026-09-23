#pragma once

namespace platform
{
	uint64_t bnet_get_userid();
	const char* bnet_get_username();
	void set_revamped_username(const std::string& name);
	std::string get_userdata_directory();
}