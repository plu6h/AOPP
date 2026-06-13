#include "PatternFinder.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstring>
#include <iostream>

PatternFinder::PatternFinder(const std::string& module)
{

	const auto handle = GetModuleHandleA(module.c_str());
	if (handle == nullptr)
		return;
	
	_data = reinterpret_cast<signed char*>(handle);

	_baseAddress = reinterpret_cast<int>(_data);
	
	PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(_data);
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		throw std::runtime_error("Image is not a valid PE file");

	auto pImageHeader = reinterpret_cast<PIMAGE_NT_HEADERS>((char*)pDosHeader + pDosHeader->e_lfanew);
	if (pImageHeader->Signature != IMAGE_NT_SIGNATURE)
		throw std::runtime_error("Image is not a valid NT PE file");

	auto pSecHeader = IMAGE_FIRST_SECTION(pImageHeader);
	
	for (size_t i = 0; i < pImageHeader->FileHeader.NumberOfSections; i++)
	{
		if (!strcmp(reinterpret_cast<const char*>(pSecHeader->Name), ".text"))
		{
			SizeOfCode = pSecHeader->Misc.VirtualSize;
			CodeBase = pSecHeader->VirtualAddress;
			_dataLength = CodeBase + SizeOfCode;
			return;
		}
		pSecHeader++;
		std::cout << i << std::endl;
	}

}

std::vector<int> HexToBytes(const std::string& hex)
{
	std::vector<int> bytes;

	for (unsigned int i = 0; i < hex.length(); )
	{
		if (hex[i] == '?')
		{
			if (hex[i + 1] == '?')
				i++;
			i++;
			bytes.push_back(-1);
			continue;
		}
		if (hex[i] == ' ')
		{
			i++;
			continue;
		}

		std::string byteString = hex.substr(i, 2);
		const char byte = static_cast<char>(strtol(byteString.c_str(), nullptr, 16));
		bytes.push_back(byte);
		i += 2;
	}

	return bytes;
}


std::vector<intptr_t> PatternFinder::FindPattern(const std::string& pattern) const
{
	std::vector<intptr_t> results;

	auto res = Find(HexToBytes(pattern));
	for (int& re : res)
	{
		re = re +_baseAddress;
	}
	return res;
}

std::vector<intptr_t> PatternFinder::FindPattern(const std::string& pattern, const std::function<intptr_t(intptr_t)>&
                                                 visitor) const
{
	std::vector<intptr_t> results;

	auto res = Find(HexToBytes(pattern));
	for (int& re : res)
	{
		re = re + _baseAddress;
		re = visitor(re);
	}
	return res;
}

std::vector<intptr_t> PatternFinder::Find(std::vector<int> &&  pattern) const
{
	std::vector<intptr_t> ret;
	const int plen = static_cast<int>(pattern.size());

	// Restrict the scan to the .text section: [CodeBase, CodeBase + SizeOfCode).
	// Offsets stay relative to the module base, so callers are unaffected.
	if (plen == 0 || _dataLength - CodeBase < plen)
		return ret;

	// Find the longest contiguous run of non-wildcard bytes; its first byte is the scan anchor.
	int runStart = 0;
	int runLen = 0;
	for (int i = 0, curStart = 0, curLen = 0; i < plen; i++)
	{
		if (pattern[i] != -1)
		{
			if (curLen == 0)
				curStart = i;
			if (++curLen > runLen)
			{
				runLen = curLen;
				runStart = curStart;
			}
		}
		else
		{
			curLen = 0;
		}
	}

	// An all-wildcard pattern would match everywhere; treat it as no match.
	if (runLen == 0)
		return ret;

	// Use the SIMD-optimized CRT memchr to jump between candidate positions of the
	// anchor byte, then verify the full pattern (wildcards included) around each hit.
	// A pattern match at offset 'i' places the anchor at 'i + runStart', so anchor
	// candidates live in [CodeBase + runStart, _dataLength - plen + runStart].
	const unsigned char anchor = static_cast<unsigned char>(pattern[runStart]);
	signed char* it = _data + CodeBase + runStart;
	signed char* const end = _data + _dataLength - plen + runStart + 1;
	while (it < end)
	{
		it = static_cast<signed char*>(memchr(it, anchor, end - it));
		if (!it)
			break;
		const int i = static_cast<int>(it - _data) - runStart;
		if (ByteMatch(_data, i, pattern))
			ret.push_back(i);
		++it;
	}
	return ret;
}

bool PatternFinder::ByteMatch(signed char* bytes, int start, std::vector<int>& pattern)
{
	for (int i = start, j = 0; j < static_cast<int>(pattern.size()); i++, j++)
	{
		if (pattern[j] == -1)
			continue;

		if (bytes[i] != pattern[j])
			return false;
	}
	return true;
}
