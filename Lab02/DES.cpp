// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using namespace std;
using std::cerr;
using std::cout;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::byte;
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "cryptopp/filters.h"
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/des.h"
using CryptoPP::DES_EDE2;

#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

int main(int argc, char *argv[])
{
	AutoSeededRandomPool prng;

	SecByteBlock key(DES_EDE2::DEFAULT_KEYLENGTH);
	prng.GenerateBlock(key, key.size());

	byte iv[DES_EDE2::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	string plain = "";
	cout << "Enter message: " << endl;
	getline(cin, plain);

	string cipher, encoded, recovered;

	/*********************************\
	\*********************************/

	// Pretty print key
	encoded.clear();
	StringSource(key, key.size(), true,
				 new HexEncoder(
					 new StringSink(encoded)) // HexEncoder
	);										  // StringSource
	cout << "key: " << encoded << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
				 new HexEncoder(
					 new StringSink(encoded)) // HexEncoder
	);										  // StringSource
	cout << "iv: " << encoded << endl;

	/*********************************\
	\*********************************/

	try
	{
		cout << "plain text: " << plain << endl;

		CBC_Mode<DES_EDE2>::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource(plain, true,
					 new StreamTransformationFilter(e,
													new StringSink(cipher)) // StreamTransformationFilter
		);																	// StringSource
	}
	catch (const CryptoPP::Exception &e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	// Pretty print
	encoded.clear();
	StringSource(cipher, true,
				 new HexEncoder(
					 new StringSink(encoded)) // HexEncoder
	);										  // StringSource
	cout << "cipher text: " << encoded << endl;

	/*********************************\
	\*********************************/

	try
	{
		CBC_Mode<DES_EDE2>::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true,
					   new StreamTransformationFilter(d,
													  new StringSink(recovered)) // StreamTransformationFilter
		);																		 // StringSource

		cout << "recovered text: " << recovered << endl;
	}
	catch (const CryptoPP::Exception &e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	return 0;
}
