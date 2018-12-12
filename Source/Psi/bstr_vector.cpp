#include "bstr_vector.hpp"

#include <Windows.h>

namespace psi {

bstr_vector::~bstr_vector()
{
	for (BSTR const& string : strings_)
		SysFreeString(string);
}

void bstr_vector::add(std::string const& string)
{
	return add(converter_.from_bytes(string));
}

void bstr_vector::add(std::wstring const& string)
{
	strings_.push_back(SysAllocString(string.c_str()));
}

bool bstr_vector::populate(void** output)
{
	if (output != nullptr)
	{
		SAFEARRAYBOUND bound;
		bound.lLbound = 0;
		bound.cElements = static_cast<ULONG>(strings_.size());

		if ((*output = SafeArrayCreate(VT_BSTR, 1, &bound)) != nullptr)
		{
			for (ULONG index = 0; index < bound.cElements; index++)
			{
				if (FAILED(SafeArrayPutElement(reinterpret_cast<SAFEARRAY*>(*output), reinterpret_cast<LONG*>(&index), strings_[index])))
					return false;
			}

			return true;
		}
	}

	return false;
}

} // namespace psi