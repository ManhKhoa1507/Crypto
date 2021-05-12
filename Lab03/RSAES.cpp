// Sample.cpp

#include "../include/cryptopp/stdafx.h"

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

#include "cryptopp/cryptlib.h"
using CryptoPP::DecodingResult;
using CryptoPP::Exception;
using CryptoPP::BufferedTransformation;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include <string>
using std::string;

#include <exception>
using std::exception;

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

void Save(const string& filename, const BufferedTransformation& bt)
{
    FileSink file(filename.c_str());

    bt.CopyTo(file);
    file.MessageEnd();
}

void SaveHex(const string& filename, const BufferedTransformation& bt)
{
    HexEncoder encoder;

    bt.CopyTo(encoder);
    encoder.MessageEnd();

    Save(filename, encoder);
}

void SaveHexPublicKey(const string& filename, const RSA::PublicKey& key)
{
    CryptoPP::ByteQueue queue;
    key.Save(queue);

    SaveHex(filename, queue);
}

void SaveHexPrivateKey(const string& filename, const RSA::PrivateKey& key)
{
    CryptoPP::ByteQueue queue;
    key.Save(queue);

    SaveHex(filename, queue);
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

        RSA::PrivateKey privateKey(parameters);
        RSA::PublicKey publicKey(parameters);

        SaveHexPrivateKey("rsaprivate.pem",privateKey);
        SaveHexPublicKey("rsapublic.pem",publicKey);

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
