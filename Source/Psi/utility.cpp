#include "utility.hpp"

#include <chrono>
#include <iostream>
#include <string>

namespace psi {
namespace utility {

uint8_t ascii_to_digit(char ascii)
{
	if (ascii >= '0' && ascii <= '9')
		return (ascii - '0');
	else if (ascii >= 'a' && ascii <= 'f')
		return 10 + (ascii - 'a');
	else if (ascii >= 'A' && ascii <= 'F')
		return 10 + (ascii - 'A');
	else
		throw std::logic_error("[ascii_to_byte] invalid ascii char");
}

uint8_t ascii_to_byte(char high, char low)
{
	return ((ascii_to_digit(high) << 4) | ascii_to_digit(low));
}

void timed_event(std::string const& description, std::function<void()> functor)
{
	auto start = std::chrono::high_resolution_clock::now();
	std::cout << description << std::endl;

	try
	{
		functor();
	}
	catch (std::exception const& e)
	{
		std::cout << "Exception: " << e.what() << std::endl;
	}

	auto end = std::chrono::high_resolution_clock::now();
	auto time_span = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);

	std::cout << "Finished in " << time_span.count() << " seconds" << std::endl;
}

} // namespace utility
} // namespace psi