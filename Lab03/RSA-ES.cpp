// Sample.cpp
#include "cryptopp/stdafx.h"

#include "cryptopp/rsa.h"
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;

#include "cryptopp/sha.h"
using CryptoPP::SHA1;

#include "cryptopp/filters.h"
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/queue.h"
using CryptoPP::ByteQueue;

#include "cryptopp/cryptlib.h"
using CryptoPP::DecodingResult;
using CryptoPP::Exception;
using CryptoPP::BufferedTransformation;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "cryptopp/dsa.h"
using CryptoPP::DSA;

#include "cryptopp/rsa.h"
using CryptoPP::RSA;

#include "cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;

#include "cryptopp/base64.h"
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;

#include <string>
using std::string;

#include <exception>
using std::exception;


#include <stdexcept>
using std::runtime_error;

#include <iostream>
using std::cerr;
using std::cin;
using std::cout;
using std::endl;

#include <assert.h>

#include <typeinfo>

string PrettyPrintString(string str)
{
    // Pretty print a string
    string encoded = "";

    // HexEncoder
    StringSource(str, true,
                 new HexEncoder(
                     new StringSink(encoded)));

    return encoded;
}

void Save(const string &filename, const BufferedTransformation &bt)
{
	FileSink file(filename.c_str());

	bt.CopyTo(file);
	file.MessageEnd();
}

void SavePrivateKey(const string &filename, const PrivateKey &key)
{
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void SavePublicKey(const string &filename, const PublicKey &key)
{
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void SaveBase64(const string &filename, const BufferedTransformation &bt)
{
	Base64Encoder encoder;

	bt.CopyTo(encoder);
	encoder.MessageEnd();

	Save(filename, encoder);
}

void SaveBase64PrivateKey(const string &filename, const PrivateKey &key)
{
	ByteQueue queue;
	key.Save(queue);

	SaveBase64(filename, queue);
}

void SaveBase64PublicKey(const string &filename, const PublicKey &key)
{
	ByteQueue queue;
	key.Save(queue);

	SaveBase64(filename, queue);
}

void Load(const string &filename, BufferedTransformation &bt)
{
	FileSource file(filename.c_str(), true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();
}

void LoadPrivateKey(const string &filename, PrivateKey &key)
{
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);
}

void LoadPublicKey(const string &filename, PublicKey &key)
{
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);
}

void LoadBase64PrivateKey(const string &filename, PrivateKey &key)
{
	throw runtime_error("Not implemented");
}

void LoadBase64PublicKey(const string &filename, PublicKey &key)
{
	throw runtime_error("Not implemented");
}

void LoadBase64(const string &filename, BufferedTransformation &bt)
{
	throw runtime_error("Not implemented");
}

int StringToWString(std::wstring &ws, const std::string &s)
{
    std::wstring wsTmp(s.begin(), s.end());

    ws = wsTmp;

    return 0;
}

int main(int argc, char *argv[])
{
    try
    {
        string plain, cipher, recovered;
        // Generate keys
        AutoSeededRandomPool rng;

        InvertibleRSAFunction parameters;
        parameters.GenerateRandomWithKeySize(rng, 1024);

        RSA::PrivateKey privateKey;//(parameters);
        RSA::PublicKey publicKey;//(parameters);

        LoadPrivateKey("rsa-private.ley",privateKey);

        privateKey.GetModulus();

        cout << "Enter text: ";
        getline(cin, plain);

        cout << "plaintext: " << plain << std::endl;

        // Encryption
        RSAES_OAEP_SHA_Encryptor e(publicKey);

        StringSource(plain, true,
                     new PK_EncryptorFilter(rng, e,
                                            new StringSink(cipher)) // PK_EncryptorFilter
        );                                                          // StringSource

        string prettyCipher = PrettyPrintString(cipher);
        cout << "cipher: " << prettyCipher << std::endl;

        // Decryption
        RSAES_OAEP_SHA_Decryptor d(privateKey);

        StringSource(cipher, true,
                     new PK_DecryptorFilter(rng, d,
                                            new StringSink(recovered)) // PK_EncryptorFilter
        );                                                             // StringSource

        cout << "recovered: " << recovered << std::endl;

        assert(plain == recovered);
    }
    catch (CryptoPP::Exception &e)
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }

    return 0;
}
