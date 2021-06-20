// ECDSA.KeyGen.cpp : Defines the entry point for the console application.
//

#include <assert.h>

#include <iostream>
using std::cerr;
using std::cin;
using std::cout;
using std::endl;
using std::wcin;
using std::wcout;
using std::wifstream;
using std::wstring;
using std::wstringstream;

#include <locale>
using std::locale;

#include <assert.h>
#include <ctime>
#include <codecvt>
#include <fcntl.h>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <fstream>
#include <codecvt>
#include <string>
using std::string;

#include "cryptopp/osrng.h"
// using CryptoPP::AutoSeededX917RNG;
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/integer.h"
#include "cryptopp/nbtheory.h"
using CryptoPP::Integer;

#include "cryptopp/sha.h"
using CryptoPP::SHA1;

#include "cryptopp/filters.h"
using CryptoPP::ArraySink;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::SignerFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/files.h"
using CryptoPP::byte;
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/eccrypto.h"
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::ECDSA;
using CryptoPP::ECP;

#include "cryptopp/oids.h"
using CryptoPP::OID;
// Hex encode, decode
#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

// Funtions
void LoadPrivateKey(const string &filename, ECDSA<ECP, SHA1>::PrivateKey &key);
void LoadPublicKey(const string &filename, ECDSA<ECP, SHA1>::PublicKey &key);

bool SignMessage(const ECDSA<ECP, SHA1>::PrivateKey &key, const string &message, string &signature);
bool VerifyMessage(const ECDSA<ECP, SHA1>::PublicKey &key, const string &message, const string &signature);

// convert UTF-8 string to wstring
wstring utf8_to_wstring(const std::string &str)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> myconv;
    return myconv.from_bytes(str);
}

// convert wstring to UTF-8 string
string wstring_to_utf8(const std::wstring &str)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> myconv;
    return myconv.to_bytes(str);
}

wstring ReadFile(const char *filename)
{
    std::wifstream wif(filename);
    wif.imbue(std::locale(std::locale(), new std::codecvt_utf8<wchar_t>));
    std::wstringstream wss;
    wss << wif.rdbuf();
    return wss.str();
}

void CreateSignature()
{
    // Create the signature

    // Load secret key
    ECDSA<ECP, SHA1>::PrivateKey privateKey;
    LoadPrivateKey("ec.private.key", privateKey);

    wstring wMessage, wSignature;
    string message, signature;

    wMessage = ReadFile("message.txt");
    wcout << "input message: " << wMessage << endl;

    message = wstring_to_utf8(wMessage);

    int start_s = clock();
    for (int i = 0; i < 10000; i++)
    {
        AutoSeededRandomPool prng;
        //Siging message
        signature.erase();
        StringSource(message, true,
                     new SignerFilter(prng,
                                      ECDSA<ECP, SHA1>::Signer(privateKey),
                                      new HexEncoder(new StringSink(signature))));
    }
    int stop_s = clock();
    double total = (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000;

    wcout << "signature (r,s):" << utf8_to_wstring(signature) << endl;
    wcout << "\nTotal time for 10.000 rounds: " << total << " ms" << endl;
    wcout << "\nExecution time: " << total / 10000 << " ms" << endl
          << endl;
}

void VerifySignature()
{
    // Verify the signature

    bool result;

    ECDSA<ECP, SHA1>::PublicKey publicKey;
    LoadPublicKey("ec.public.key", publicKey);

    wstring wMessage, wSignature;
    string message, signature, signature_r;

    wMessage = ReadFile("message.txt");
    wSignature = ReadFile("signature.txt");

    message = wstring_to_utf8(wMessage);
    signature = wstring_to_utf8(wSignature);

    // Hex decode signature

    StringSource ss(signature, true,
                    new HexDecoder(
                        new StringSink(signature_r)) // HexDecoder
    );

    int start_s = clock();
    for (int i = 0; i < 10000; i++)
    {
        result = VerifyMessage(publicKey, message, signature_r);
    }
    // if result == 0 invalid otherwise is valid
    int stop_s = clock();
    double total = (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000;
    
    wcout << "Verify the signature on m: " << result << endl;
    wcout << "\nTotal time for 10.000 rounds: " << total << " ms" << endl;
    wcout << "\nExecution time: " << total / 10000 << " ms" << endl
          << endl;
}

int main(int argc, char *argv[])
{
    int osType;

#ifdef __linux__
    setlocale(LC_ALL, "");
    osType = 1;
#elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
    osType = 2;
#else
#endif
    // Scratch result
    int mode;
    wcout << "Please create message.txt or signature.txt first!" << endl;
    wcout << "(1)Create Signature (2)Verify the Message: ";
    fflush(stdin);
    wcin >> mode;

    if (mode == 1)
    {
        wcout << "Creating Signature" << endl;
        CreateSignature();
    }

    else
    {
        wcout << "Verifying your signature" << endl;
        VerifySignature();
    }

    return 0;
}

/* Def functions*/

void LoadPrivateKey(const string &filename, ECDSA<ECP, SHA1>::PrivateKey &key)
{
    key.Load(FileSource(filename.c_str(), true /*pump all*/).Ref());
}

void LoadPublicKey(const string &filename, ECDSA<ECP, SHA1>::PublicKey &key)
{
    key.Load(FileSource(filename.c_str(), true /*pump all*/).Ref());
}

bool SignMessage(const ECDSA<ECP, SHA1>::PrivateKey &key, const string &message, string &signature)
{
    AutoSeededRandomPool prng;

    signature.erase();

    StringSource(message, true,
                 new SignerFilter(prng,
                                  ECDSA<ECP, SHA1>::Signer(key),
                                  new StringSink(signature)) // SignerFilter
    );                                                       // StringSource

    return !signature.empty();
}

bool VerifyMessage(const ECDSA<ECP, SHA1>::PublicKey &key, const string &message, const string &signature)
{
    bool result = false;

    StringSource(signature + message, true,
                 new SignatureVerificationFilter(
                     ECDSA<ECP, SHA1>::Verifier(key),
                     new ArraySink((byte *)&result, sizeof(result))) // SignatureVerificationFilter
    );

    return result;
}
