#include "include.hpp"

int main(int arg_c, char** arg_v)
{
	if (arg_c != 2)
	{
		printf("[-] usage: hook_finder.exe process_name.exe\n");
		return -1;
	}

	std::uint32_t process_id = memory::find_process_id(arg_v[1]);
	if (!process_id)
	{
		printf("[-] failed to find process [%s]\n", arg_v[1]);
		return -1;
	}

	printf("[+] found [%s] process id [0x%x]\n", arg_v[1], process_id);

	HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
	if (!process_handle || process_handle == INVALID_HANDLE_VALUE)
	{
		printf("[-] failed to open handle to process [%s]\n", process_id);
		return -1;
	}

	printf("[+] opened handle to process [0x%x]\n", process_handle);

	SymSetOptions(SYMOPT_UNDNAME);
	SymInitialize(process_handle, nullptr, TRUE);

	zydis::disassembler disassembler{};

	auto module_array = memory::get_process_modules(process_handle, process_id);

	printf("[+] found [%i] loaded modules\n", static_cast<int>(module_array.size()));

	scanner_search scanner{};

	scanner.disassembler = &disassembler;
	scanner.process_handle = process_handle;
	scanner.module_search = &module_array;

	int hooks_found = scanner::scan_process_modules(&scanner);

	CloseHandle(process_handle);

	printf("[+] found [%i] jmp hooks\n", hooks_found);

	return 0;
}