// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cerr;
using std::cin;
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

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/modes.h"
using CryptoPP::ECB_Mode;

int main(int argc, char *argv[])
{
    AutoSeededRandomPool prng;

    byte key[AES::DEFAULT_KEYLENGTH];
    prng.GenerateBlock(key, sizeof(key));

    string plain = "";
    cout << "Enter input: ";
    getline(cin, plain);

    string cipher, encoded, recovered;

    /*********************************\
	\*********************************/

    // Pretty print key
    encoded.clear();
    StringSource(key, sizeof(key), true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    cout << "key: " << encoded << endl;

    /*********************************\
	\*********************************/

    try
    {
        cout << "plain text: " << plain << endl;

        ECB_Mode<AES>::Encryption e;
        e.SetKey(key, sizeof(key));

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource(plain, true,
                     new StreamTransformationFilter(e,
                                                    new StringSink(cipher)) // StreamTransformationFilter
        );                                                                  // StringSource
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
    );                                        // StringSource
    cout << "cipher text: " << encoded << endl;

    /*********************************\
	\*********************************/

    try
    {
        ECB_Mode<AES>::Decryption d;
        d.SetKey(key, sizeof(key));

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource

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
