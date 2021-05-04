#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cerr;
using std::cin;
using std::cout;
using std::endl;
using std::string;

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

#include "cryptopp/ccm.h"
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;

#include "assert.h"

string EncryptCBC(string plain, byte key[], byte iv[])
{
    string cipher;
    int keyLength = AES::DEFAULT_KEYLENGTH;
    CBC_Mode<AES>::Encryption e;

    e.SetKeyWithIV(key, keyLength, iv);

    // The StreamTransformationFilter removes
    // padding as required.
    // StringSource
    // StreamTransformationFilter
    StringSource s(plain, true,
                   new StreamTransformationFilter(e,
                                                  new StringSink(cipher)));
    return cipher;
}

string DecryptCBC(string cipher, byte key[], byte iv[])
{
    string plain;
    CBC_Mode<AES>::Decryption d;
    int keyLength = AES::DEFAULT_KEYLENGTH;

    d.SetKeyWithIV(key, keyLength, iv);

    // The StreamTransformationFilter removes
    //  padding as required.
    // StreamTransformationFilter
    // StringSource
    StringSource s(cipher, true,
                   new StreamTransformationFilter(d,
                                                  new StringSink(plain)));

    return plain;
}

string EncryptCFB(string plain, byte key[], byte iv[])
{
    string cipher;
    int keyLength = AES::DEFAULT_KEYLENGTH;
    CFB_Mode<AES>::Encryption e;

    e.SetKeyWithIV(key, keyLength, iv);

    // The StreamTransformationFilter removes
    // padding as required.
    // StringSource
    // StreamTransformationFilter
    StringSource s(plain, true,
                   new StreamTransformationFilter(e,
                                                  new StringSink(cipher)));
    return cipher;
}

string DecryptCFB(string cipher, byte key[], byte iv[])
{
    string plain;
    CFB_Mode<AES>::Decryption d;
    int keyLength = AES::DEFAULT_KEYLENGTH;

    d.SetKeyWithIV(key, keyLength, iv);

    // The StreamTransformationFilter removes
    //  padding as required.
    // StreamTransformationFilter
    // StringSource
    StringSource s(cipher, true,
                   new StreamTransformationFilter(d,
                                                  new StringSink(plain)));

    return plain;
}

string EncryptECB(string plain, byte key[])
{
    string cipher;
    int keyLength = AES::DEFAULT_KEYLENGTH;
    ECB_Mode<AES>::Encryption e;

    e.SetKey(key, keyLength);

    // The StreamTransformationFilter removes
    // padding as required.
    // StringSource
    // StreamTransformationFilter
    StringSource s(plain, true,
                   new StreamTransformationFilter(e,
                                                  new StringSink(cipher)));
    return cipher;
}

string DecryptECB(string cipher, byte key[])
{
    string plain;
    ECB_Mode<AES>::Decryption d;
    int keyLength = AES::DEFAULT_KEYLENGTH;

    d.SetKey(key, keyLength);

    // The StreamTransformationFilter removes
    //  padding as required.
    // StreamTransformationFilter
    // StringSource
    StringSource s(cipher, true,
                   new StreamTransformationFilter(d,
                                                  new StringSink(plain)));

    return plain;
}

string EncryptOFB(string plain, byte key[], byte iv[])
{
    string cipher;
    int keyLength = AES::DEFAULT_KEYLENGTH;
    OFB_Mode<AES>::Encryption e;

    e.SetKeyWithIV(key, keyLength, iv);

    // The StreamTransformationFilter removes
    // padding as required.
    // StringSource
    // StreamTransformationFilter
    StringSource s(plain, true,
                   new StreamTransformationFilter(e,
                                                  new StringSink(cipher)));
    return cipher;
}

string DecryptOFB(string cipher, byte key[], byte iv[])
{
    string plain;
    OFB_Mode<AES>::Decryption d;
    int keyLength = AES::DEFAULT_KEYLENGTH;

    d.SetKeyWithIV(key, keyLength, iv);

    // The StreamTransformationFilter removes
    //  padding as required.
    // StreamTransformationFilter
    // StringSource
    StringSource s(cipher, true,
                   new StreamTransformationFilter(d,
                                                  new StringSink(plain)));

    return plain;
}

string PrettyPrintByte(byte byteList[])
{
    // Pretty print a byte list
    string encoded = "";

    // HexEncoder
    StringSource(byteList, sizeof(byteList), true,
                 new HexEncoder(
                     new StringSink(encoded)));

    return encoded;
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

void printException(CryptoPP::Exception e)
{
    cerr << e.what() << endl;
    exit(1);
}

void AES_CBC(string plain)
{
    AutoSeededRandomPool prng;

    byte key[AES::DEFAULT_KEYLENGTH];
    prng.GenerateBlock(key, sizeof(key));

    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    string cipher, encoded, recovered;

    // Pretty print key
    string prettyKey = PrettyPrintByte(key);
    cout << "key: " << prettyKey << endl;

    // Pretty print iv
    string prettyIV = PrettyPrintByte(iv);
    cout << "iv: " << prettyIV << endl;

    try
    {
        cout << "plain text: " << plain << endl;
        cipher = EncryptCBC(plain, key, iv);

#if 0
		StreamTransformationFilter filter(e);
		filter.Put((const byte*)plain.data(), plain.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		cipher.resize(ret);
		filter.Get((byte*)cipher.data(), cipher.size());
#endif
    }
    catch (const CryptoPP::Exception &e)
    {
        printException(e);
    }

    // Pretty print cipher text
    string prettyCipher = PrettyPrintString(cipher);
    cout << "cipher text: " << prettyCipher << endl;

    try
    {
        recovered = DecryptCBC(cipher, key, iv);

#if 0
		StreamTransformationFilter filter(d);
		filter.Put((const byte*)cipher.data(), cipher.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		recovered.resize(ret);
		filter.Get((byte*)recovered.data(), recovered.size());
#endif

        cout << "recovered text: " << recovered << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        printException(e);
    }
}

void AES_CFB(string plain)
{
    AutoSeededRandomPool prng;

    byte key[AES::DEFAULT_KEYLENGTH];
    prng.GenerateBlock(key, sizeof(key));

    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    string cipher, encoded, recovered;

    // Pretty print key
    string prettyKey = PrettyPrintByte(key);
    cout << "key: " << prettyKey << endl;

    // Pretty print iv
    string prettyIV = PrettyPrintByte(iv);
    cout << "iv: " << prettyIV << endl;

    try
    {
        cout << "plain text: " << plain << endl;
        cipher = EncryptCFB(plain, key, iv);
    }
    catch (const CryptoPP::Exception &e)
    {
        printException(e);
    }

    // Pretty print cipher
    string prettyCipher = PrettyPrintString(cipher);
    cout << "cipher text: " << prettyCipher << endl;

    try
    {
        recovered = DecryptCFB(cipher, key, iv);
        cout << "recovered text: " << recovered << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        printException(e);
    }
}

void AES_ECB(string plain)
{
    AutoSeededRandomPool prng;

    byte key[AES::DEFAULT_KEYLENGTH];
    prng.GenerateBlock(key, sizeof(key));

    string cipher, encoded, recovered;

    // Pretty print key
    string prettyKey = PrettyPrintByte(key);
    cout << "key: " << prettyKey << endl;

    try
    {
        cout << "plain text: " << plain << endl;
        cipher = EncryptECB(plain, key);
    }
    catch (const CryptoPP::Exception &e)
    {
        printException(e);
    }

    string prettyCipher = PrettyPrintString(cipher);
    cout << "cipher text: " << prettyCipher << endl;

    try
    {
        recovered = DecryptECB(cipher, key);
        cout << "recovered text: " << recovered << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        printException(e);
    }
}

void AES_OFB(string plain)
{
    AutoSeededRandomPool prng;

    byte key[AES::DEFAULT_KEYLENGTH];
    prng.GenerateBlock(key, sizeof(key));

    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    string cipher, encoded, recovered;

    // Pretty print key
    string prettyKey = PrettyPrintByte(key);
    cout << "key: " << prettyKey << endl;

    // Pretty print iv
    string prettyIV = PrettyPrintByte(iv);
    cout << "key: " << prettyIV << endl;

    try
    {
        cout << "plain text: " << plain << endl;
        cipher = EncryptOFB(plain, key, iv);
    }
    catch (const CryptoPP::Exception &e)
    {
        printException(e);
    }

    // Pretty print cipher
    string prettyCipher = PrettyPrintString(cipher);
    cout << "cipher: " << prettyCipher << endl;

    try
    {
        recovered = DecryptOFB(cipher, key, iv);
        cout << "recovered text: " << recovered << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        printException(e);
    }
}

void GetInput(int &mode, string &plain)
{
    // Choose the mode and get the message
    cout << "(1)CBC (2)CFB (3)ECB (4)OFB: ";
    cin >> mode;
    cin.ignore();

    // Get the input
    cout << "Enter input: ";
    getline(cin, plain);
}

void ModeExecute(int mode, string plain)
{
    switch (mode)
    {
    case 1:
        cout << "AES Mode CBC\n";
        AES_CBC(plain);
        break;

    case 2:
        cout << "AES Mode CFB\n";
        AES_CFB(plain);
        break;

    case 3:
        cout << "AES Mode ECB\n";
        AES_ECB(plain);
        break;

    case 4:
        cout << "AES Mode OFB\n";
        AES_OFB(plain);
        break;
    }
}

int main(int argc, char *argv[])
{
    string plain = "";
    int mode;

    GetInput(mode, plain);
    ModeExecute(mode, plain);

    return 0;
}