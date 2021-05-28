// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
/* Work on files*/
#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::BufferedTransformation;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

#include <iostream>
using std::wcin;
using std::wcout;
using std::cerr;
using std::endl;

#include <string>
using std::string;
using std::wstring;

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::Redirector; // string to bytes

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/ccm.h"
using CryptoPP::CBC_Mode;
#include "assert.h"

/* Set _setmode()*/ 
#ifdef _WIN32
#include <io.h> 
#include <fcntl.h>
#else
#endif
/* Convert string*/ 
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;
wstring string_to_wstring (const std::string& str);
string wstring_to_string (const std::wstring& str);

int main(int argc, char* argv[])
{	
	#ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif
	AutoSeededRandomPool prng;
	byte key[32], fkey[32];
	/* Create random key and write to file*/
	/*
	prng.GenerateBlock(fkey, sizeof(fkey));
	StringSource ss(fkey, sizeof(fkey), true , new FileSink( "AES_key.key"));
	*/

	/* Reading key from file*/
	FileSource fs("AES_key.key", false);
	/*Create space  for key*/ 
	CryptoPP::ArraySink copykey(key, sizeof(key));
	/*Copy data from AES_key.key  to  key */ 
	fs.Detach(new Redirector(copykey));
	fs.Pump(sizeof(key));  // Pump first 32 bytes
	
	/*
	wstring wskey;
	wcout<<"Please input key (32 bytes): ";
	wcin.ignore();
	getline(wcin,wskey);
	string skey;
	skey= wstring_to_string(wskey);
	StringSource ss(skey, false);
	CryptoPP::ArraySink copykey(key, sizeof(key));
	ss.Detach(new Redirector(copykey));
	ss.Pump(16);  // Pump first 16 bytes
	*/

	byte iv[AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));
	wstring wplain;
	wcout << "Input plain text:";
	//wcin.ignore();
	getline(wcin,wplain); 
	string plain;
	plain=wstring_to_string(wplain);
	string cipher, encoded, recovered;

	/*********************************\
	\*********************************/

	// Pretty print key
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded) << endl;

	/*********************************\
	\*********************************/

	try
	{
		wcout << "plain text: " << wplain << endl;

		CBC_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)
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
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "cipher text: " << string_to_wstring(encoded) << endl;

	/*********************************\
	\*********************************/

	try
	{
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource


		wcout << "recovered text: " << string_to_wstring(recovered) << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	return 0;
}

/* convert string to wstring */
wstring string_to_wstring (const std::string& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string wstring_to_string (const std::wstring& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}
