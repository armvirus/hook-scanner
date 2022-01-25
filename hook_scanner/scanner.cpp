#include "include.hpp"

namespace scanner
{
	std::string find_module_name(scanner_search* scanner, std::uintptr_t address)
	{
		for (auto enumerated_module : *scanner->module_search)
		{
			const auto& [remote_module_base, module_size, module_path, module_name] = enumerated_module;
			if (!remote_module_base) continue;

			if (address > remote_module_base && address < remote_module_base + module_size)
				return module_name + "+" + memory::hex_to_string(address - remote_module_base, false);
		}

		return memory::hex_to_string(address, true);
	}

	int analyze_module(scanner_search* scanner, module_search* module_data)
	{
		int hooks_found = 0;
		ZyanU64 runtime_address = module_data->remote_module_base + module_data->text_va;

		std::uintptr_t local_loaded_text_section = module_data->local_loaded_module_buffer + module_data->text_raw;
		std::uintptr_t local_copied_text_section = module_data->copied_image_address + module_data->text_va;

		for (ZyanUSize offset = 0; offset < module_data->text_size;)
		{
			auto [status, instruction, operands] = scanner->disassembler->disassemble_instruction((void*)(local_copied_text_section + offset), module_data->text_size - offset);
			if (ZYAN_SUCCESS(status))
			{
				if (memcmp(reinterpret_cast<void*>(local_loaded_text_section + offset), reinterpret_cast<void*>(local_copied_text_section + offset), instruction->length) != 0)
				{
					std::string export_name = memory::pe_viewer::find_module_export_by_rva(module_data->copied_image_address, runtime_address - module_data->remote_module_base);

					switch (instruction->mnemonic)
					{
					case ZYDIS_MNEMONIC_JMP:
					{
						std::uintptr_t jmp_destination{};
						jmp_destination = scanner->disassembler->get_instruction_absolute_address(*instruction, operands, runtime_address);
						if (*reinterpret_cast<std::uint16_t*>(local_copied_text_section + offset) == 0x25FF)
						{
							jmp_destination = *reinterpret_cast<std::uintptr_t*>(local_copied_text_section + offset + instruction->length);
						}
						else
						{
							jmp_destination = scanner->disassembler->get_instruction_absolute_address(*instruction, operands, runtime_address);
						}

						std::string jmp_destination_formatted = find_module_name(scanner, jmp_destination);

						auto [copied_jmp, success] = memory::read_remote_memory<jmp_inst_array>(scanner->process_handle, jmp_destination);
						if (success == false) break;

						auto [absolute_jmp_status, absolute_jmp_instruction, absolute_jmp_operands] = scanner->disassembler->disassemble_instruction(&copied_jmp, sizeof(jmp_inst_array));

						if (ZYAN_SUCCESS(absolute_jmp_status) && absolute_jmp_instruction->mnemonic == ZYDIS_MNEMONIC_JMP)
						{
							std::uintptr_t absolute_jmp_destination{};

							if (copied_jmp.opcode[0] == 0xFF && copied_jmp.opcode[1] == 0x25)
							{
								absolute_jmp_destination = *reinterpret_cast<std::uintptr_t*>(&copied_jmp.opcode[absolute_jmp_instruction->length]);
							}
							else
							{
								absolute_jmp_destination = scanner->disassembler->get_instruction_absolute_address(*absolute_jmp_instruction, absolute_jmp_operands, jmp_destination);
							}

							std::string absolute_jmp_destination_formatted = find_module_name(scanner, absolute_jmp_destination);
							printf("[2] [%p] [%s + %s] [jmp %s]\n", runtime_address, module_data->module_name.c_str(), export_name.c_str(), absolute_jmp_destination_formatted.c_str());
						}
						else
						{
							printf("[1] [%p] [%s + %s] [jmp %s]\n", runtime_address, module_data->module_name.c_str(), export_name.c_str(), jmp_destination_formatted.c_str());
						}

						hooks_found++;

						break;
					}
					case ZYDIS_MNEMONIC_INT3:
					{
						std::string instruction_buffer = scanner->disassembler->format_instruction(*instruction, operands, runtime_address);
						printf("[0] [%p] [%s + %s] [%s]\n", runtime_address, module_data->module_name.c_str(), export_name.c_str(), instruction_buffer.c_str());
						break;
					}
					case ZYDIS_MNEMONIC_NOP:
					{
						std::string instruction_buffer = scanner->disassembler->format_instruction(*instruction, operands, runtime_address);
						printf("[0] [%p] [%s + %s] [%s]\n", runtime_address, module_data->module_name.c_str(), export_name.c_str(), instruction_buffer.c_str());
						break;
					}
					default:
					{
						break;
					}
					}
				}
			}

			offset += instruction->length;
			runtime_address += instruction->length;
		}

		return hooks_found;
	}

	int scan_process_modules(scanner_search* scanner)
	{
		int hooks_found = 0;

		for (auto enumerated_module : *scanner->module_search)
		{
			const auto& [remote_module_base, module_size, module_path, module_name] = enumerated_module;
			if (!remote_module_base || 
				module_name.find(".dll") == std::string::npos || 
				module_name.find("d3dcompiler") != std::string::npos ||
				module_name.find("D3DCOMPILER") != std::string::npos ||
				module_name.find("dbghelp") != std::string::npos ||
				module_name.find("stub.dll") != std::string::npos ||
				module_name.find("XAudio") != std::string::npos) 
				continue;

			module_search module_data{};

			module_data.module_name = module_name;
			module_data.remote_module_base = remote_module_base;

			std::vector<std::uint8_t>buffer{};
			memory::pe_viewer::read_file_to_memory(module_path, &buffer);

			module_data.local_loaded_module_buffer = reinterpret_cast<std::uintptr_t>(buffer.data());
			if (!module_data.local_loaded_module_buffer) continue;

			auto [text_va, text_raw, text_size] = memory::pe_viewer::get_process_section_info(module_data.local_loaded_module_buffer, ".text");

			module_data.text_va = text_va;
			module_data.text_raw = text_raw;
			module_data.text_size = text_size;

			module_data.copied_image_address = reinterpret_cast<std::uintptr_t>(VirtualAlloc(0, module_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
			ReadProcessMemory(scanner->process_handle, reinterpret_cast<LPCVOID>(module_data.remote_module_base), reinterpret_cast<LPVOID>(module_data.copied_image_address), module_size, 0);

			hooks_found += analyze_module(scanner, &module_data);

			VirtualFree(reinterpret_cast<void*>(module_data.copied_image_address), 0, MEM_RELEASE);
		}

		return hooks_found;
	}
}