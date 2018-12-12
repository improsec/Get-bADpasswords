#include "hash_file.hpp"

#include <Windows.h>

namespace psi {

hash_file::hash_file() :
	handle_(INVALID_HANDLE_VALUE),
	size_(0),
	elements_(0)
{

}

hash_file::~hash_file()
{
	close();
}

void hash_file::open(std::string const& filename)
{
	close();

	if ((handle_ = CreateFileA(filename.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL)) == INVALID_HANDLE_VALUE)
		throw std::runtime_error("cannot open file");
	else
	{
		LARGE_INTEGER file_size;
		memset(&file_size, 0, sizeof(LARGE_INTEGER));
		
		if (!GetFileSizeEx(handle_, &file_size))
			throw std::runtime_error("cannot query file size");
		else if (read(&elements_, sizeof(uint64_t)) != sizeof(uint64_t))
			throw std::runtime_error("cannot read entire element count object");
		else
			size_ = (static_cast<uint64_t>(file_size.QuadPart) - sizeof(uint64_t));
	}
}

void hash_file::close()
{
	if (handle_ != INVALID_HANDLE_VALUE)
	{
		CloseHandle(handle_);
		handle_ = INVALID_HANDLE_VALUE;
	}

	size_ = 0;
	elements_ = 0;
}

void hash_file::reset() const
{
	if (handle_ == INVALID_HANDLE_VALUE)
		throw std::runtime_error("cannot reset uninitialized file");
	else if (SetFilePointer(handle_, sizeof(uint64_t), NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR)
		throw std::runtime_error("cannot reset file pointer");
}

uint32_t hash_file::read(void* const buffer, std::size_t length) const
{
	if (handle_ == INVALID_HANDLE_VALUE)
		throw std::runtime_error("cannot read from uninitialized file");
	else
	{
		DWORD bytes_read = 0;

		if (!ReadFile(handle_, buffer, static_cast<DWORD>(length), &bytes_read, NULL))
			throw std::runtime_error("cannot read file data");
		else
			return static_cast<uint32_t>(bytes_read);
	}
}

uint64_t hash_file::size() const
{
	return size_;
}

uint64_t hash_file::elements() const
{
	return elements_;
}

} //  namespace psi