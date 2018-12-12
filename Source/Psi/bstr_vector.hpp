#pragma once

#include <codecvt>
#include <string>
#include <vector>

namespace psi {

class bstr_vector
{
public:
	~bstr_vector();

	void add(std::string const& string);
	void add(std::wstring const& string);

	bool populate(void** output);

private:
	std::vector<wchar_t*> strings_;
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter_;
};

} // namespace psi