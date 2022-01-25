#pragma once

struct jmp_inst_array
{
	std::uint8_t opcode[ZYDIS_MAX_INSTRUCTION_LENGTH - 1];
};
namespace zydis
{
	class disassembler
	{
	public:
		disassembler();
		std::tuple< ZyanStatus, ZydisDecodedInstruction*, ZydisDecodedOperand*> disassemble_instruction(void* instruction_address, std::uint32_t instruction_length);
		ZyanU64 get_instruction_absolute_address(ZydisDecodedInstruction& instruction, ZydisDecodedOperand* operands, ZyanU64 runtime_address);
		std::string format_instruction(ZydisDecodedInstruction& instruction, ZydisDecodedOperand* operands, ZyanU64 runtime_address);

	private:
		ZydisFormatter formatter;
		ZydisDecoder decoder;
	};
}