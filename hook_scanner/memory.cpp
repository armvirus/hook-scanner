#include "include.hpp"

namespace memory
{
	std::uint32_t find_process_id(std::string process_name)
	{
		PROCESSENTRY32 process_info;
		process_info.dwSize = sizeof(process_info);

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

		Process32First(snapshot, &process_info);
		if (!process_name.compare(process_info.szExeFile))
		{
			CloseHandle(snapshot);
			return process_info.th32ProcessID;
		}

		while (Process32Next(snapshot, &process_info))
		{
			if (!process_name.compare(process_info.szExeFile))
			{
				CloseHandle(snapshot);
				return process_info.th32ProcessID;
			}
		}

		CloseHandle(snapshot);
		return 0;
	}

	void nt_suspend_process(HANDLE handle)
	{
		reinterpret_cast<long(*)(HANDLE)>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSuspendProcess"))(handle);
	}

	void nt_resume_process(HANDLE handle)
	{
		reinterpret_cast<long(*)(HANDLE)>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtResumeProcess"))(handle);
	}

	std::vector<std::tuple<std::uintptr_t, std::uint32_t, std::string, std::string>> get_process_modules(HANDLE process_handle, std::uint32_t process_id)
	{
		std::vector<std::tuple<std::uintptr_t, std::uint32_t, std::string, std::string>>process_modules{};

		MODULEENTRY32 module_info;
		module_info.dwSize = sizeof(module_info);

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);

		Module32First(snapshot, &module_info);
		auto [dos, success_dos] = memory::read_remote_memory<IMAGE_DOS_HEADER>(process_handle, reinterpret_cast<std::uintptr_t>(module_info.modBaseAddr));
		auto [nt, success_nt] = memory::read_remote_memory<IMAGE_NT_HEADERS>(process_handle, reinterpret_cast<std::uintptr_t>(module_info.modBaseAddr) + dos.e_lfanew);

		process_modules.push_back(std::tuple<std::uintptr_t, std::uint32_t, std::string, std::string>(reinterpret_cast<std::uintptr_t>(module_info.modBaseAddr), nt.OptionalHeader.SizeOfImage, module_info.szExePath, module_info.szModule));

		std::uintptr_t main_module = reinterpret_cast<std::uintptr_t>(module_info.modBaseAddr);

		while (Module32Next(snapshot, &module_info))
		{
			// When querying both 32 and 64bit modules, the main exe will be included twice
			if (reinterpret_cast<std::uintptr_t>(module_info.modBaseAddr) != main_module)
			{
				auto [dos, success_dos] = memory::read_remote_memory<IMAGE_DOS_HEADER>(process_handle, reinterpret_cast<std::uintptr_t>(module_info.modBaseAddr));
				auto [nt, success_nt] = memory::read_remote_memory<IMAGE_NT_HEADERS>(process_handle, reinterpret_cast<std::uintptr_t>(module_info.modBaseAddr) + dos.e_lfanew);

				process_modules.push_back(std::tuple<std::uintptr_t, std::uint32_t, std::string, std::string>(reinterpret_cast<std::uintptr_t>(module_info.modBaseAddr), nt.OptionalHeader.SizeOfImage, module_info.szExePath, module_info.szModule));
			}
		}

		return process_modules;
	}

	template <typename t> 
	t read_memory(HANDLE handle, std::uintptr_t address)
	{
		t buffer{};

		if (ReadProcessMemory(handle, reinterpret_cast<LPCVOID>(address), reinterpret_cast<LPVOID>(&buffer), sizeof(t), 0))
			return buffer;

		return t{};
	}

	std::string hex_to_string(std::uintptr_t hex, bool pointer)
	{
		char hex_string[64];

		sprintf_s(hex_string, pointer == true ? "0x%p" : "0x%x", hex);

		return std::string(hex_string);
	}

	namespace pe_viewer
	{
		std::tuple<std::uint32_t, std::uint32_t, std::uint32_t> get_process_section_info(std::uintptr_t module_base, std::string section_name)
		{
			if (module_base == 0)
				return {};

			const auto module_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module_base);

			if (module_dos_header->e_magic != IMAGE_DOS_SIGNATURE)
				return{};

			const auto module_nt_headers32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(module_base + module_dos_header->e_lfanew);
			if (module_nt_headers32->Signature != IMAGE_NT_SIGNATURE)
				return{};

			WORD section_count;
			PIMAGE_SECTION_HEADER section_headers;
			if (module_nt_headers32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
			{
				const auto module_nt_headers64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(module_base + module_dos_header->e_lfanew);
				section_count = module_nt_headers64->FileHeader.NumberOfSections;
				section_headers = IMAGE_FIRST_SECTION(module_nt_headers64);
			}
			else
			{
				section_count = module_nt_headers32->FileHeader.NumberOfSections;
				section_headers = IMAGE_FIRST_SECTION(module_nt_headers32);
			}

			for (WORD i = 0; i < section_count; ++i)
			{
				if (strcmp(reinterpret_cast<char*>(section_headers[i].Name), section_name.c_str()) == 0)
				{
					return { section_headers[i].VirtualAddress, section_headers[i].PointerToRawData, section_headers[i].Misc.VirtualSize };
				}
			}

			return {};
		}

		std::string find_module_export_by_rva(std::uintptr_t image_base, std::uint32_t export_offset)
		{
			PIMAGE_DOS_HEADER dos_headers = reinterpret_cast<PIMAGE_DOS_HEADER>(image_base);
			if (dos_headers->e_magic != IMAGE_DOS_SIGNATURE) return {};

			PIMAGE_NT_HEADERS32 nt_headers32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(image_base + dos_headers->e_lfanew);
			if (nt_headers32->Signature != IMAGE_NT_SIGNATURE) return {};
			std::uint32_t exports_rva;
			if (nt_headers32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
			{
				PIMAGE_NT_HEADERS64 nt_headers64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(image_base + dos_headers->e_lfanew);
				exports_rva = nt_headers64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			}
			else
			{
				exports_rva = nt_headers32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			}

			if (!exports_rva) return {};

			PIMAGE_EXPORT_DIRECTORY exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(image_base + exports_rva);
			std::uint32_t* name_rva = reinterpret_cast<std::uint32_t*>(image_base + exports->AddressOfNames);

			for (std::uint32_t i = 0; i < exports->NumberOfNames; ++i)
			{
				char* function_name = reinterpret_cast<char*>(image_base + name_rva[i]);
				std::uint32_t* function_rva = reinterpret_cast<std::uint32_t*>(image_base + exports->AddressOfFunctions);
				std::uint16_t* ordinal_rva = reinterpret_cast<std::uint16_t*>(image_base + exports->AddressOfNameOrdinals);

				if (!function_name || !function_rva || !ordinal_rva || !function_rva[ordinal_rva[i]]) continue;

				if (function_rva[ordinal_rva[i]] == export_offset)
				{
					return function_name;
				}
			}

			return hex_to_string(export_offset, false);
		}

		bool read_file_to_memory(const std::string& file_path, std::vector<uint8_t>* out_buffer)
		{
			std::ifstream file_ifstream(file_path, std::ios::binary);

			if (!file_ifstream)
				return false;

			out_buffer->assign((std::istreambuf_iterator<char>(file_ifstream)), std::istreambuf_iterator<char>());
			file_ifstream.close();

			return true;
		}
	}
}