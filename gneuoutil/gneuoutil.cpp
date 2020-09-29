// This file is part of gneuoutil.
// Copyright (c) 2020 Piotr "Xeno" Adamczyk

// ReSharper disable CppClangTidyClangDiagnosticShorten64To32

#define VERSION "1.0.0"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

using std::cout;
using std::endl;

const BYTE nwr_encryption_key[] = {
	0xF9, 0xAB, 0x50, 0xA1, 0x62, 0x3B, 0x03, 0xE0,
	0xED, 0x55, 0xA7, 0xEB, 0x40, 0x16, 0xF1, 0x32,
	0xD0, 0xDA, 0x48, 0xB8, 0xB7, 0x1A, 0x69, 0xDD,
	0x49, 0x81, 0xD8, 0x0C, 0xD8, 0x57, 0xD4, 0x6A
};

const DWORD nwr_encryption_key_length = 0x20;

BYTE* nw_decrypt_resource(BYTE* data, int length, DWORD offset)
{
	BYTE* c_ptr = data;
	for (auto i = 0; i < length; i++)
	{
		const DWORD key_offset = reinterpret_cast<DWORD>(c_ptr + (offset - reinterpret_cast<DWORD>(data))) % nwr_encryption_key_length;
		*c_ptr = (*c_ptr + 0x8dU ^ *const_cast<BYTE*>(nwr_encryption_key + key_offset)) + 0x8c;
		c_ptr += 1;
	}
	return data;
}

BYTE* nw_encrypt_resource(BYTE* data, int length, DWORD offset)
{
	BYTE* c_ptr = data;
	for (auto i = 0; i < length; i++)
	{
		const DWORD key_offset = reinterpret_cast<DWORD>(c_ptr + (offset - reinterpret_cast<DWORD>(data))) % nwr_encryption_key_length;
		*c_ptr = (*c_ptr + 0x74U ^ *const_cast<BYTE*>(nwr_encryption_key + key_offset)) + 0x73;
		c_ptr += 1;
	}
	return data;
}

void usage()
{
	cout << "Example usage:" << endl
		<< "  gneuoutil decrypt <in_file.nwr> <out_file.nos>" << endl
		<< "  gneuoutil encrypt <in_file.nos> <out_file.nwr>" << endl
		<< "  gneuoutil help" << endl;
}

int main(int argc, char** argv)
{
	cout << "gneuoutil " << VERSION " (" << __DATE__ << " " __TIME__ << ")" << endl;

	if (argc < 2)
	{
		usage();
		return 1;
	}
	
	std::string command = std::string(argv[1]);
	std::transform(command.begin(), command.end(), command.begin(),
			[](unsigned char c) { return char(std::tolower(c)); });
	
	if(command == "help")
	{
		usage();
		cout << endl << "\x67\x6e\x65\x75\x67\x6e\x65\x75\x67\x6e\x65\x75\x20\x62\x6c"
		     << "\x6f\x77\x61\x20\x74\x68\x69\x6e\x6b\x20\x68\x65\x20\x67\x6f\x6f\x64"
		     << "\x20\x7e\x20\x42\x6c\x6f\x77\x61\x2c\x20\x41\x70\x72\x20\x30\x38\x20"
			 << "\x32\x30\x32\x30" << endl;
		return 0;
	}

	if(argc != 4 || (command != "decrypt" && command != "encrypt"))
	{
		usage();
		return 1;
	}

	const char* in_file = argv[2];
	const char* out_file = argv[3];
	
	std::ifstream input_stream(in_file, std::ios_base::binary);

	input_stream.seekg(0, std::ios_base::end);
	const int input_length = int(input_stream.tellg());
	input_stream.seekg(0, std::ios_base::beg);

	BYTE* file = new BYTE[input_length];
	input_stream.read(reinterpret_cast<char*>(file), input_length);

	if(command == "decrypt")
	{
		nw_decrypt_resource(file, input_length, 0);
	}
	else if (command == "encrypt")
	{
		nw_encrypt_resource(file, input_length, 0);
	}
	
	std::ofstream output_stream(out_file, std::ios_base::binary);
	output_stream.write(reinterpret_cast<const char*>(file), input_length);

	cout << "Success!" << endl;

	delete[] file;
	return 0;
}
