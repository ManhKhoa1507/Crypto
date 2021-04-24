// time.cpp : Defines the entry point for the console application.
//g++ -o TimeSHA3-512.exe TimeSHA3-512.cpp -DNDEBUG -g2 -O3 -D_WIN32_WINNT=0x0501 -pthread ./lib/libcryptopp.a
#include <ctime>
#include <string>
#include <iostream>

// Include cryptopp header files
#include "./include/cryptopp/sha3.h"
#include "./include/cryptopp/filters.h"
#include "./include/cryptopp/hex.h"

using CryptoPP::byte;
using CryptoPP::SHA3_512;
using namespace std;

string PrettyOutput(byte *out)
{
	// Print hash output in hex form
	string output;
	CryptoPP::HexEncoder encoder;

	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(out, 64);
	encoder.MessageEnd();

	return output;
}

string sha3(string input)
{
	// Hash the message using the sha3-512
	CryptoPP::SHA3_512 hash3;
	byte *buffer = (unsigned char *)malloc(input.size());
	byte *out = (unsigned char *)malloc(hash3.DigestSize());

	hash3.Restart();

	memcpy(buffer, input.data(), input.size());

	hash3.Update(buffer, input.size());
	hash3.Final(out);

	// Get the prettier output
	string output = PrettyOutput(out);
	return output;
}

double CalHashTime(string input)
{
	// Calculate the hash time of 1 round
	int start_s = clock();
	sha3(input);
	int stop_s = clock();

	double etime = (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000;
	return etime;
}

double CalTotalTime(string input)
{
	// Calculate total time of 10000 rounds
	double total = 0;
	int a = 1;

	while (a < 10000)
	{
		total = total + CalHashTime(input);
		a = a + 1;
	}
	return total;
}

void GetInput(string &input)
{
	// Get the input
	cout << "Please enter the input message: ";
	cin >> input;
}

void DisplayResult(string output, double total)
{
	// Display result (cipherText, total time to hash 10000 rounds and Execution time)
	cout << "DES output: " << output << endl;
	cout << "Total time for 10.000 rounds: " << total << " ms" << endl;
	cout << "Execution time: " << total / 10000 << " ms" << endl
		 << endl;
}

int main()
{
	string input;
	GetInput(input);

	string output = sha3(input);
	double total = CalTotalTime(input);

	DisplayResult(output, total);
	return 0;
}