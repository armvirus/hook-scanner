#include "include.hpp"

zydis::disassembler::disassembler()
{
	ZydisDecoderInit(&this->decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
	ZydisFormatterInit(&this->formatter, ZYDIS_FORMATTER_STYLE_INTEL);
	ZydisFormatterSetProperty(&this->formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);
}

std::tuple< ZyanStatus, ZydisDecodedInstruction*, ZydisDecodedOperand*> zydis::disassembler::disassemble_instruction(void* instruction_address, std::uint32_t instruction_length)
{
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];
	ZyanStatus status = ZydisDecoderDecodeFull(&this->decoder, instruction_address, instruction_length, &instruction, operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY);

	return { status, &instruction, operands };
}

ZyanU64 zydis::disassembler::get_instruction_absolute_address(ZydisDecodedInstruction& instruction, ZydisDecodedOperand* operands, ZyanU64 runtime_address)
{
	auto destination = 0ULL;

	for (int i = 0; i < instruction.operand_count; i++)
	{
		if ((operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operands[i].imm.is_relative == TRUE) || operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY)
		{
			ZydisCalcAbsoluteAddress(&instruction, &operands[i], runtime_address, &destination);
			break;
		}

		if (operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operands[i].imm.is_relative == FALSE)
		{
			destination = operands[i].imm.value.u;
			break;
		}
	}

	return destination;
}

ZydisRegister zydis::disassembler::get_instruction_register(ZydisDecodedInstruction& instruction, ZydisDecodedOperand* operands)
{
	for (int i = 0; i < instruction.operand_count; i++)
	{
		if (operands[i].type == ZYDIS_OPERAND_TYPE_REGISTER)
		{
			return operands[i].reg.value;
		}
	}

	return ZYDIS_REGISTER_NONE;
}

std::string zydis::disassembler::format_instruction(ZydisDecodedInstruction& instruction, ZydisDecodedOperand* operands, ZyanU64 runtime_address)
{
	char buffer[256];
	ZydisFormatterFormatInstruction(&this->formatter, &instruction, operands, instruction.operand_count_visible, buffer, sizeof(buffer), runtime_address);

	return buffer;
}
