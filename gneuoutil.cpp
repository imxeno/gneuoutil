// This file is part of gneuoutil.
// Copyright (c) 2020 Piotr "Xeno" Adamczyk

#include <vector>
#include <iostream>
#include <fstream>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

const BYTE nwr_encryption_key[] = {
	0xF9, 0xAB, 0x50, 0xA1, 0x62, 0x3B, 0x03, 0xE0,
	0xED, 0x55, 0xA7, 0xEB, 0x40, 0x16, 0xF1, 0x32,
	0xD0, 0xDA, 0x48, 0xB8, 0xB7, 0x1A, 0x69, 0xDD,
	0x49, 0x81, 0xD8, 0x0C, 0xD8, 0x57, 0xD4, 0x6A
};

const DWORD nwr_encryption_key_length = 0x20;

BYTE* nw_decrypt_resource(BYTE* data, DWORD length, DWORD offset)
{
	BYTE* cptr = data;
	for (int i = 0; i < length; i++)
	{
		DWORD key_offset = (DWORD)(cptr + (offset - (DWORD)data)) % nwr_encryption_key_length;
		*cptr = (*cptr + 0x8dU ^ *(BYTE*)(nwr_encryption_key + key_offset)) + 0x8c;
		cptr += 1;
	}
	return data;
}

BYTE* nw_encrypt_resource(BYTE* data, DWORD length, DWORD offset)
{
	BYTE* cptr = data;
	for (int i = 0; i < length; i++)
	{
		DWORD key_offset = (DWORD)(cptr + (offset - (DWORD)data)) % nwr_encryption_key_length;
		*cptr = (*cptr + 0x74U ^ *(BYTE*)(nwr_encryption_key + key_offset)) + 0x73;
		cptr += 1;
	}
	return data;
}


int main(int argc, char** argv)
{
	std::ifstream infile(argv[1], std::ios_base::binary);

	infile.seekg(0, std::ios_base::end);
	const size_t length = infile.tellg();
	infile.seekg(0, std::ios_base::beg);

	BYTE* file = new BYTE[length];
	infile.read((char*)file, length);
	nw_decrypt_resource(file, length, 0);
	std::ofstream outfile(std::string(argv[1]) + ".dec", std::ios_base::binary);
	outfile.write((const char*)file, length);
	nw_encrypt_resource(file, length, 0);
	std::ofstream outfile2(std::string(argv[1]) + ".dec.enc", std::ios_base::binary);
	outfile2.write((const char*)file, length);
	delete file;
}
