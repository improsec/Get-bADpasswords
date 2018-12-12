#include "hash_scanner.hpp"
#include "utility.hpp"

namespace psi {

void hash_scanner::source_add(std::string const& filename)
{
	sources_.push_back(hash_file());
	sources_.back().open(filename);
}

void hash_scanner::source_clear()
{
	sources_.clear();
	sources_.shrink_to_fit();
}

void hash_scanner::test(char** input, int count, bstr_vector& matches)
{
	/*
		We should maintain a continuous memory usage of maximum 2 MB or less for the hash-data container
		If the processing is too slow, try increasing the maximum memory usage to 1 GB (or more)
	*/
	static constexpr uint64_t usage = 512000000;

	for (hash_file const& source : sources_)
	{
		source.reset();

		for (uint64_t remains = source.size(), processed = 0; remains > 0; remains -= processed)
		{
			read(source, static_cast<std::size_t>(processed = std::min<uint64_t>(remains, usage)));

			for (int i = 0; i < count; i++)
			{
				if (find(input[i]))
					matches.add(input[i]);
			}
		}
	}

	data_.clear();
	data_.shrink_to_fit();
}

void hash_scanner::read(hash_file const& source, std::size_t size)
{
	if ((size % 16) != 0)
		throw std::logic_error("cannot read hashes to a non-aligned buffer");
	else
	{
		data_.clear();
		data_.reserve(size / 16);

		std::vector<uint8_t> buffer;

		for (uint32_t length = 0; size > 0; )
		{
			std::array<uint8_t, 16 * 1024> temp;

			while ((length = source.read(&temp[0], std::min<std::size_t>(temp.size(), size - buffer.size()))) != 0)
			{
				buffer.insert(buffer.end(), temp.begin(), temp.begin() + length);
				std::vector<uint8_t>::const_iterator iterator = buffer.cbegin();

				while (iterator != buffer.cend() && std::distance(iterator, buffer.cend()) >= 16)
				{
					data_.push_back(hash_data());
					std::copy(iterator, iterator + 16, data_.back().data());

					std::advance(iterator, 16);
					size -= 16;
				}

				buffer.erase(buffer.begin(), iterator);
			}
		}
	}
}

bool hash_scanner::find(std::array<uint8_t, 16> const& entry) const
{
	return std::binary_search(data_.begin(), data_.end(), entry);
}

bool hash_scanner::find(std::string const& str) const
{
	std::array<uint8_t, 16> entry;

	if (!utility::hex_to_array(entry, str.begin(), str.end()))
		return false;
	else
		return std::binary_search(data_.begin(), data_.end(), entry);
}

} //  namespace psi