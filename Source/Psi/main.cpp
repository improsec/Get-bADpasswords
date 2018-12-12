#include "hash_scanner.hpp"
#include "utility.hpp"

#include <Windows.h>

#ifndef DllExport
#define DllExport	__declspec(dllexport) __stdcall
#endif

namespace psi {

static hash_scanner scanner;

void open_input(char const* filename)
{
	utility::timed_event("Opening input file...", [&]() -> void
	{
		scanner.source_add(filename);
	});
}

void clear_input()
{
	utility::timed_event("Clearing input data...", [&]() -> void
	{
		scanner.source_clear();
	});
}

void test_hashes(char** input, int count, SAFEARRAY** output)
{
	bstr_vector matches;

	utility::timed_event("Scanning for hashes...", [&]() -> void
	{
		scanner.test(input, count, matches);
		matches.populate(reinterpret_cast<void**>(output));
	});
}

} // namespace psi

#ifdef __cplusplus
extern "C" {
#endif

void DllExport AddSource(char const* filename)
{
	psi::open_input(filename);
}

void DllExport ClearSources()
{
	psi::clear_input();
}

void DllExport TestHashes(char** input, int count, SAFEARRAY** output)
{
	psi::test_hashes(input, count, output);
}

#ifdef __cplusplus
}
#endif

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpvReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		/* On library being loaded */
	}

	return TRUE;
}