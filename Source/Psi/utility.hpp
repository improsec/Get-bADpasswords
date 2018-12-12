#pragma once

#include <array>
#include <functional>

namespace psi {
namespace utility {

uint8_t ascii_to_digit(char ascii);
uint8_t ascii_to_byte(char high, char low);

template <std::size_t Size>
constexpr inline bool hex_to_array(std::array<uint8_t, Size>& output, std::string const& hex_string)
{
	try
	{
		for (std::size_t i = 0, j = 0; i < Size && j < hex_string.size(); i++, j += 2)
			output[i] = ascii_to_byte(hex_string[j], hex_string[j + 1]);
	}
	catch (std::exception const&)
	{
		return false;
	}

	return true;
}

template <std::size_t Size, typename Iterator>
constexpr inline bool hex_to_array(std::array<uint8_t, Size>& output, Iterator begin, Iterator end)
{
	try
	{
		for (std::size_t i = 0; (i < Size) && begin != end && std::next(begin) != end; i++, std::advance(begin, 2))
			output[i] = ascii_to_byte(*begin, *std::next(begin));
	}
	catch (std::exception const&)
	{
		return false;
	}

	return true;
}

void timed_event(std::string const& description, std::function<void()> functor);

} // namespace utility
} // namespace psi