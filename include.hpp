#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <tlhelp32.h>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <DbgHelp.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment (lib, "imagehlp.lib")
#include <Zydis/Zydis.h>

#include "memory.hpp"
#include "disassembler.hpp"
#include "scanner.hpp"
