#pragma once

#include "bstr_vector.hpp"
#include "hash_file.hpp"

#include <array>

namespace psi {

class hash_scanner
{
	using hash_data = std::array<uint8_t, 16>;

public:
	void source_add(std::string const& filename);
	void source_clear();

	void test(char** input, int count, bstr_vector& matches);

private:
	void read(hash_file const& source, std::size_t elements);

	bool find(std::array<uint8_t, 16> const& entry) const;
	bool find(std::string const& str) const;

private:
	std::vector<hash_file> sources_;
	std::vector<hash_data> data_;
};

} // namespace psi