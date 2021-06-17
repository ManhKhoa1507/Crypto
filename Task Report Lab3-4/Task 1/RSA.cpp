// Sample.cpp

#include "./stdafx.h"

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

// convert UTF-8 string to wstring
std::wstring utf8_to_wstring(const std::string &str)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> myconv;
    return myconv.from_bytes(str);
}

// convert wstring to UTF-8 string
std::string wstring_to_utf8(const std::wstring &str)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> myconv;
    return myconv.to_bytes(str);
}

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

wstring ReadFile(const char *filename)
{
    std::wifstream wif(filename);
    wif.imbue(std::locale(std::locale(), new std::codecvt_utf8<wchar_t>));
    std::wstringstream wss;
    wss << wif.rdbuf();
    return wss.str();
}

void SaveFile(const char *filename, wstring wstr)
{
    std::wofstream f(filename);
    f << wstr;
    f.close();
}

void RSAEncryption()
{
    // Encryption

    wstring wPlain, wCipher;
    string plain, cipher;

    // Load public key
    RSA::PublicKey publicKey;
    LoadKey("rsa-public.key", publicKey);
    wcout << "You choose encryption!" << endl;

    int chooseMode;
    wcout << "(1)Input from screen (2)Input from file message.txt: ";
    wcin >> chooseMode;
    wcout << endl;

    if (chooseMode == 1)
    {
        //Input from screen
        wcout << "Please enter your message: ";
        fflush(stdin);
        wcin >> wPlain;
    }
    else
    {
        //Input from file
        wPlain = ReadFile("message.txt");
    }

    wcout << "Plaintext: " << wPlain << endl;
    plain = wstring_to_utf8(wPlain);

    int start_s = clock();
    for (int i = 0; i < 10000; i++)
    {
        cipher.clear();

        // Encryption
        AutoSeededRandomPool rng;
        RSAES_OAEP_SHA_Encryptor e(publicKey);
        StringSource ss1(plain, true,
                         new PK_EncryptorFilter(rng, e,
                                                new StringSink(cipher)) // PK_EncryptorFilter
        );
    }
    int stop_s = clock();
    double total = (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000;

    // Pretty print the cipher
    string encoded;

    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(
                     new StringSink(encoded)));

    wstring encodedCipher(encoded.begin(), encoded.end());
    wcout << "Ciphertext in hex: " << encodedCipher << endl;

    wcout << "\nTotal time for 10.000 rounds: " << total << " ms" << endl;
    wcout << "\nExecution time: " << total / 10000 << " ms" << endl
          << endl;
}

void RSADecryption()
{

    // Load private key
    RSA::PrivateKey privateKey;
    LoadKey("rsa-private.key", privateKey);

    wstring wRecovered, wCipher, wMessage;
    string recovered, cipher, message;

    wcout << "You choose decryption!" << endl;

    int chooseMode;
    wcout << "(1)Input from screen (2)Input from file cipher.txt: ";
    wcin >> chooseMode;
    wcout << endl;

    if (chooseMode == 1)
    {
        //Input from screen
        wcout << "Please enter your message: ";
        fflush(stdin);
        wcin >> wMessage;
    }
    else
    {
        //Input from file
        wMessage = ReadFile("cipher.txt");
    }

    wcout << "Ciphertext: " << wMessage << endl
          << endl;
    StringSource ss(wstring_to_utf8(wMessage), true, new HexDecoder(new StringSink(cipher)));

    int start_s = clock();
    for (int i = 0; i < 10000; i++)
    {
        // Decryption
        recovered.clear();
        AutoSeededRandomPool rng;
        RSAES_OAEP_SHA_Decryptor d(privateKey);
        StringSource(cipher, true,
                     new PK_DecryptorFilter(rng, d,
                                            new StringSink(recovered)) // PK_EncryptorFilter
        );
    }
    int stop_s = clock();
    double total = (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000;

    wcout << "Recovered : " << utf8_to_wstring(recovered);
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

    int mode;
    wcout << "Please choose mode : (1)Encryption (2)Decryption: ";
    wcin >> mode;
    wcout << endl;

    wstring wPlain, wCipher, wRecovered;
    string plain, cipher, recovered;

    if (mode == 1)
    {
        RSAEncryption();
    }
    else
    {
        RSADecryption();
    }
    return 0;
}