#pragma once

struct module_search
{
	std::string module_name;

	std::uintptr_t remote_module_base;
	std::uintptr_t local_loaded_module_buffer;

	std::uintptr_t copied_image_address;

	std::uint32_t text_va;
	std::uint32_t text_raw;
	std::uint32_t text_size;
};

struct scanner_search
{
	zydis::disassembler* disassembler;
	std::vector<std::tuple<std::uintptr_t, std::uint32_t, std::string, std::string>>* module_search;
	HANDLE process_handle;
};

namespace scanner
{
	int scan_process_modules(scanner_search* scanner);
}