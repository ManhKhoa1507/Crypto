#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cerr;
using std::cin;
using std::cout;
using std::endl;
using std::string;
using std::wcin;
using std::wcout;

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
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::Redirector;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/ccm.h"
using CryptoPP::CBC_Mode;
using CryptoPP::CCM;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;

#include "cryptopp/gcm.h"
using CryptoPP::GCM;

#include "cryptopp/xts.h"
using CryptoPP::XTS;
using CryptoPP::XTS_Mode;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "assert.h"

#include <ctime>
#include <codecvt>
#include <locale>
#include <fcntl.h>
#include <cstdlib>
#include <cstring>
using std::wstring;

// convert UTF-8 string to wstring
std::wstring Utf8ToWstring(const std::string &str)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> myconv;
    return myconv.from_bytes(str);
}

// convert wstring to UTF-8 string
std::string WstringToUtf8(const std::wstring &str)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> myconv;
    return myconv.to_bytes(str);
}

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

string EncryptCTR(string plain, byte key[], byte iv[])
{
    string cipher;
    CTR_Mode<AES>::Encryption e;

    int keyLength = AES::DEFAULT_KEYLENGTH;
    e.SetKeyWithIV(key, keyLength, iv);

    StringSource(plain, true,
                 new StreamTransformationFilter(e,
                                                new StringSink(cipher)) // StreamTransformationFilter
    );
    return cipher;
}

string EncryptXTS(string plain, byte key[], byte iv[])
{
    string cipher;
    XTS_Mode<AES>::Encryption enc;

    int keyLength = 64;
    enc.SetKeyWithIV(key, keyLength, iv);

#if 0
        std::cout << "key length: " << enc.DefaultKeyLength() << std::endl;
        std::cout << "key length (min): " << enc.MinKeyLength() << std::endl;
        std::cout << "key length (max): " << enc.MaxKeyLength() << std::endl;
        std::cout << "block size: " << enc.BlockSize() << std::endl;
#endif

    StringSource ss(plain, true,
                    new StreamTransformationFilter(enc,
                                                   new StringSink(cipher),
                                                   StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
    );                                                                                     // StringSource
    return cipher;
}

string EncryptCCM(string plain, byte key[], byte iv[])
{
    string cipher;
    CCM<AES, 8>::Encryption e;
    e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
    e.SpecifyDataLengths(0, plain.size(), 0);

    StringSource(plain, true,
                 new AuthenticatedEncryptionFilter(e,
                                                   new StringSink(cipher)));
    return cipher;
}

string EncryptGCM(string plain, byte key[], byte iv[])
{
    string cipher;
    GCM<AES>::Encryption e;
    e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

    // The StreamTransformationFilter adds padding
    //  as required. GCM and CBC Mode must be padded
    //  to the block size of the cipher.
    StringSource(plain, true,
                 new AuthenticatedEncryptionFilter(e,
                                                   new StringSink(cipher)) // StreamTransformationFilter
    );
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

string DecryptCTR(string cipher, byte key[], byte iv[])
{
    string recovered;
    CTR_Mode<AES>::Decryption d;

    int keyLength = AES::DEFAULT_KEYLENGTH;
    d.SetKeyWithIV(key, keyLength, iv);

    StringSource s(cipher, true,
                   new StreamTransformationFilter(d,
                                                  new StringSink(recovered)));
    return recovered;
}

string DecryptXTS(string cipher, byte key[], byte iv[])
{
    string recovered;
    XTS_Mode<AES>::Decryption dec;

    int keyLength = 64;
    dec.SetKeyWithIV(key, keyLength, iv);

    // The StreamTransformationFilter removes
    //  padding as requiredec.
    StringSource ss(cipher, true,
                    new StreamTransformationFilter(dec,
                                                   new StringSink(recovered),
                                                   StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
    );
    return recovered;
}

string DecryptCCM(string cipher, byte key[], byte iv[])
{
    string recovered;
    CCM<AES, 8>::Decryption d;
    d.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
    d.SpecifyDataLengths(0, cipher.size() - 8, 0);

    AuthenticatedDecryptionFilter df(d,
                                     new StringSink(recovered));

    StringSource(cipher, true,
                 new Redirector(df));

    bool b = df.GetLastResult();
    assert(true == b);
    return recovered;
}

string DecryptGCM(string cipher, byte key[], byte iv[])
{
    string recovered;
    GCM<AES>::Decryption d;
    d.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

    // The StreamTransformationFilter removes
    //  padding as required.
    StringSource s(cipher, true,
                   new AuthenticatedDecryptionFilter(d,
                                                     new StringSink(recovered)) // StreamTransformationFilter
    );
    return recovered;
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

void CreateRandomKeyIV(CryptoPP::byte key[], CryptoPP::byte iv[])
{
    AutoSeededRandomPool prng;
    prng.GenerateBlock(key, sizeof(key));
    prng.GenerateBlock(iv, sizeof(iv));
}

void AES_CBC(string plain, byte key[], byte iv[])
{
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
		StreamTra  std::cout << "plain text: " << plain << std::endl;essageEnd();

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

void AES_CFB(string plain,byte key[], byte iv[])
{

#ifdef __linux__
    setlocale(LC_ALL, "");
#elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif

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

void AES_ECB(string plain, byte key[])
{

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

void AES_OFB(string plain, byte key[], byte iv[])
{

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

void AES_CTR(string plain, byte key[], byte iv[])
{
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
        cipher = EncryptCTR(plain, key, iv);
    }
    catch (const CryptoPP::Exception &e)
    {
        printException(e);
    }

    string prettyCipher = PrettyPrintString(cipher);
    cout << "cipher: " << prettyCipher << endl;

    try
    {
        recovered = DecryptCTR(cipher, key, iv);
        cout << "recovered text: " << recovered << endl;
    }

    catch (const CryptoPP::Exception &e)
    {
        printException(e);
    }
}

void AES_XTS(string plain)
{
    using namespace CryptoPP;

    AutoSeededRandomPool prng;

    SecByteBlock key(32), iv(16);
    prng.GenerateBlock(key, (key.size()));
    prng.GenerateBlock(iv, iv.size());

    std::string cipher, encoded, recovered;

    try
    {
        std::cout << "plain text: " << plain << std::endl;
        cipher = EncryptXTS(plain, key, iv);
    }

    catch (const CryptoPP::Exception &e)
    {
        printException(e);
    }

    // Pretty print key
    string prettyKey = PrettyPrintByte(key);
    cout << "key: " << prettyKey << endl;

    // Pretty print iv
    string prettyIV = PrettyPrintByte(iv);
    cout << "iv: " << prettyIV << endl;

    string prettyCipher = PrettyPrintString(cipher);
    cout << "cipher: " << prettyCipher << endl;

    try
    {
        XTS_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), iv);

        recovered = DecryptXTS(cipher, key, iv); // StringSource
        std::cout << "recovered text: " << recovered << std::endl;
    }

    catch (const CryptoPP::Exception &e)
    {
        printException(e);
    }
}

void AES_CCM(string plain, byte key[], byte iv[])
{
    AutoSeededRandomPool prng;

    // { 7, 8, 9, 10, 11, 12, 13 }

    // { 4, 6, 8, 10, 12, 14, 16 }
    const int TAG_SIZE = 8;

    // Encrypted, with Tag
    string cipher, encoded;

    // Recovered
    string recovered;

    // Pretty print key
    string prettyKey = PrettyPrintByte(key);
    cout << "key: " << prettyKey << endl;

    // Pretty print iv
    string prettyIV = PrettyPrintByte(iv);
    cout << "iv: " << prettyIV << endl;

    try
    {
        cout << "plain text: " << plain << endl;
        cipher = EncryptCCM(plain, key, iv);
    }

    catch (CryptoPP::Exception &e)
    {
        printException(e);
        cerr << endl;
    }

    string prettyCipher = PrettyPrintString(cipher);
    cout << "cipher: " << prettyCipher << endl;

    try
    {
        recovered = DecryptCCM(cipher, key, iv);
        cout << "recovered text: " << recovered << endl;
    }

    catch (CryptoPP::Exception &e)
    {
        printException(e);
        cerr << endl;
    }
}

void AES_GCM(string plain, byte key[] ,byte iv[])
{
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
        cipher = EncryptGCM(plain, key, iv); // StringSource
    }

    catch (const CryptoPP::Exception &e)
    {
        printException(e);
    }

    string prettyCipher = PrettyPrintString(cipher);
    cout << "cipher: " << prettyCipher << endl;

    try
    {
        recovered = DecryptGCM(cipher, key, iv);
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
    cout << "(1)CBC (2)CFB (3)ECB (4)OFB (5)CTR (6)XTS (7)CCM (8)GCM:";
    cin >> mode;
    cin.ignore();

    // Get the input
    cout << "Enter input: ";
    getline(cin, plain);
}

void GetKeyFromScreen(wstring &wkey)
{
    cin.ignore();
    wcout << L"Enter the key: ";
    fflush(stdin);
    getline(wcin, wkey);
    wcout << wkey;
    cout << endl;
}

void GetIVFromScreen(wstring &wiv)
{
    cin.ignore();
    wcout << L"Enter the iv: ";
    fflush(stdin);
    getline(wcin, wiv);
    cout << endl;
}

void ChooseModeKeyAndIV(int &mode)
{
    cout << "(1)Key and iv is random\n";
    cout << "(2)Key and iv from screen\n";
    cout << "(3)key and iv from file\n";
    cin >> mode;
}

void ModeRandom(int mode, string plain)
{
    CryptoPP::byte key[16];
    CryptoPP::byte iv[32];
    CreateRandomKeyIV(key, iv);

    switch (mode)
    {
    case 1:
        cout << "AES Mode CBC\n";
        AES_CBC(plain, key, iv);
        break;

    case 2:
        cout << "AES Mode CFB\n";
        AES_CFB(plain, key, iv);
        break;

    case 3:
        cout << "AES Mode ECB\n";
        AES_ECB(plain, key);
        break;

    case 4:
        cout << "AES Mode OFB\n";
        AES_OFB(plain, key, iv);
        break;

    case 5:
        cout << "AES Mode CTR\n";
        AES_CTR(plain, key, iv);
        break;
    case 6:
        cout << "AES Mode XTS\n";
        AES_XTS(plain);
        break;
    case 7:
        cout << "AES Mode CCM\n";
        AES_CCM(plain, key, iv);
    case 8:
        cout << "AES Mode GCM\n";
        AES_GCM(plain, key, iv);
        break;
    }
}

void ModeScreen(int mode, string plain)
{
    wstring wkey, wiv;
    string keyString, ivString;
    CryptoPP::byte key[100];
    CryptoPP::byte iv[100];

    wcout << L"Enter the key: ";
    // fflush(stdin);
    cin.ignore(1);
    getline(wcin, wkey);
    cout << endl;

    /* Reading key from  input screen*/
    StringSource ss(keyString, false);
    /* Create byte array space for key*/
    CryptoPP::ArraySink copykey(key, sizeof(key));
    /*Copy data to key*/
    ss.Detach(new Redirector(copykey));
    ss.Pump(16);
    // Pump first 16 bytes

    cin.ignore(1);
    wcout << L"Enter the iv: ";
    //fflush(stdin);
    cin.ignore(1);
    getline(wcin, wiv);
    cout << endl;

    /* Reading key from  input screen*/
    StringSource s1(ivString, false);
    /* Create byte array space for key*/
    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
    /*Copy data to key*/
    s1.Detach(new Redirector(copyiv));
    s1.Pump(16);
    // Pump first 16 bytes

    // switch (mode)
    // {
    // case 1:
    //     cout << "AES Mode CBC\n";
    //     AES_CBC(plain);
    //     break;

    // case 2:
    //     cout << "AES Mode CFB\n";
    //     AES_CFB(plain);
    //     break;

    // case 3:
    //     cout << "AES Mode ECB\n";
    //     AES_ECB(plain);
    //     break;

    // case 4:
    //     cout << "AES Mode OFB\n";
    //     AES_OFB(plain);
    //     break;

    // case 5:
    //     cout << "AES Mode CTR\n";
    //     AES_CTR(plain);
    //     break;
    // case 6:
    //     cout << "AES Mode XTS\n";
    //     AES_XTS(plain);
    //     break;
    // case 7:
    //     cout << "AES Mode CCM\n";
    //     AES_CCM(plain);
    // case 8:
    //     cout << "AES Mode GCM\n";
    //     AES_GCM(plain);
    //     break;
    // }
}

void ModeExecute(int keyAndIVMode, int mode, string plain)
{
    switch (keyAndIVMode)
    {
    case 1:
        cout << "Key and IV is random\n";
        ModeRandom(mode, plain);
        break;

    case 2:
        cout << "Key and IV from screen\n";
        ModeScreen(mode, plain);
        break;
    }
}

int main(int argc, char *argv[])
{

#ifdef __linux__
    setlocale(LC_ALL, "");
#elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif

    string plain = "";

    int mode, keyAndIVMode;

    GetInput(mode, plain);
    ChooseModeKeyAndIV(keyAndIVMode);
    ModeExecute(keyAndIVMode, mode, plain);

    return 0;
}