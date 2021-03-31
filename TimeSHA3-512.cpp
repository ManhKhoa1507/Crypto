// time.cpp : Defines the entry point for the console application.
//g++ -o TimeSHA3-512.exe TimeSHA3-512.cpp -DNDEBUG -g2 -O3 -D_WIN32_WINNT=0x0501 -pthread ./lib/libcryptopp.a
#include <ctime>
#include <string>

#include <iostream>
// Include cryptopp header files
#include "./include/cryptopp/sha3.h"
#include "./include/cryptopp/filters.h"
#include "./include/cryptopp/hex.h"

using CryptoPP::SHA3_512;
using namespace std;
using CryptoPP::byte;

double sha3(string input)
{
	int start_s = clock();
	double etime;

	CryptoPP::SHA3_512 hash3;
	string in = input;
	byte *buffer = (unsigned char *)malloc(in.size());
	byte *out = (unsigned char *)malloc(hash3.DigestSize());

	hash3.Restart();

	memcpy(buffer, in.data(), in.size());

	hash3.Update(buffer, in.size());
	hash3.Final(out);

	int stop_s = clock();

	etime = (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000;

	// Print hash output in hex form
	CryptoPP::HexEncoder encoder;
	std::string output;

	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(out, 64);
	encoder.MessageEnd();

	return etime;
}

int main()
{

	double result, total;

	std::string input;
	cout << "Please enter the input message: ";
	cin >> input;

	total = 0;
	int a = 1;
	
	while (a < 10001)
	{
		total = total + sha3(input);
		a = a + 1;
	}
	
	result = total / 10000;
	CryptoPP::SHA3_512 hash3;
	
	byte *buffer = (unsigned char *)malloc(input.size());
	byte *out = (unsigned char *)malloc(hash3.DigestSize());
	
	hash3.Restart();
	memcpy(buffer, input.data(), input.size());
	
	hash3.Update(buffer, input.size());
	hash3.Final(out);
	
	CryptoPP::HexEncoder encoder;
	std::string output;
	
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(out, 64);
	encoder.MessageEnd();
	std::string pause;
	
	cout << "Input size: " << input.size() << " bytes" << endl;
	cout << "SHA3-512 output: " << output << endl;
	cout << "Total time for 10.000 rounds: " << total << " ms" << endl;
	cout << "Execution time: " << result << " ms" << endl
		 << endl;
	cout << "Do you like to quite program?" << endl;

	cin >> pause;
}
