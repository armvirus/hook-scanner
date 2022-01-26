#pragma once

namespace memory
{
	std::uint32_t find_process_id(std::string process_name);
	std::vector<std::tuple<std::uintptr_t, std::uint32_t, std::string, std::string>> get_process_modules(HANDLE process_handle, std::uint32_t process_id);
	std::string hex_to_string(std::uintptr_t hex, bool pointer);

	void nt_suspend_process(HANDLE handle);
	void nt_resume_process(HANDLE handle);

	std::string get_symbol_name(HANDLE process_handle, std::uintptr_t remote_address, std::uintptr_t remote_module_base);

	template<typename type>
	std::tuple<type, bool> read_remote_memory(HANDLE process_handle, std::uintptr_t address)
	{
		type buffer{};

		if (ReadProcessMemory(process_handle, reinterpret_cast<LPCVOID>(address), &buffer, sizeof(type), 0))
			return { buffer, true};

		return { {}, false };
	}

	namespace pe_viewer
	{
		std::tuple<std::uint32_t, std::uint32_t, std::uint32_t> get_process_section_info(std::uintptr_t module_base, std::string section_name);
		std::string find_module_export_by_rva(std::uintptr_t image_base, std::uint32_t export_offset);
		bool read_file_to_memory(const std::string& file_path, std::vector<uint8_t>* out_buffer);
	}
}