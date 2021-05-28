#include "../include/cryptopp/StdAfx.h"

#include "cryptopp/rsa.h"
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSA;
using CryptoPP::RSASS;

#include "cryptopp/pssr.h"
using CryptoPP::PSS;

#include "cryptopp/sha.h"
using CryptoPP::SHA1;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/filters.h"
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::SignerFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include <string>
using std::string;

#include <iostream>
using std::cin;
using std::cout;
using std::endl;

void SaveKey(const RSA::PublicKey &PublicKey, const string &filename)
{
    // DER Encode Key - X.509 key format
    PublicKey.Save(
        FileSink(filename.c_str(), true /*binary*/).Ref());
}

void SaveKey(const RSA::PrivateKey &PrivateKey, const string &filename)
{
    // DER Encode Key - PKCS #8 key format
    PrivateKey.Save(
        FileSink(filename.c_str(), true /*binary*/).Ref());
}

void LoadKey(const string &filename, RSA::PublicKey &PublicKey)
{
    // DER Encode Key - X.509 key format
    PublicKey.Load(
        FileSource(filename.c_str(), true, NULL, true /*binary*/).Ref());
}

void LoadKey(const string &filename, RSA::PrivateKey &PrivateKey)
{
    // DER Encode Key - PKCS #8 key format
    PrivateKey.Load(
        FileSource(filename.c_str(), true, NULL, true /*binary*/).Ref());
}

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

int main(int argc, char *argv[])
{
    try
    {
        // Generate keys
        AutoSeededRandomPool rng;

        InvertibleRSAFunction parameters;
        parameters.GenerateRandomWithKeySize(rng, 1024);

        RSA::PrivateKey privateKey(parameters);
        RSA::PublicKey publicKey(parameters);


        
        SaveKey(privateKey, "signprivate.pem");
        SaveKey(publicKey, "signpublic.pem");

        // Message
        string message, signature;
        cout << "Enter text: ";
        cin >> message;

        cout << endl
             << "message: " << message << endl;

        // Sign and Encode
        RSASS<PSS, SHA1>::Signer signer(privateKey);

        StringSource(message, true,
                     new SignerFilter(rng, signer,
                                      new StringSink(signature)) // SignerFilter
        );                                                       // StringSource
        string prettySign = PrettyPrintString(signature);
        cout << endl
             << "sign: "
             << prettySign << endl;

        // Verify and Recover
        RSASS<PSS, SHA1>::Verifier verifier(publicKey);

        StringSource(message + signature, true,
                     new SignatureVerificationFilter(
                         verifier, NULL,
                         SignatureVerificationFilter::THROW_EXCEPTION) // SignatureVerificationFilter
        );                                                             // StringSource

        cout << endl
             << "Verified signature on message" << endl;

    } // try

    catch (CryptoPP::Exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
