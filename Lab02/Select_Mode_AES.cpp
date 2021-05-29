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

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

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

wstring PrettyPrintByte(byte byteList[])
{
    // Pretty print a byte list
    string encoded = "";

    // HexEncoder
    StringSource(byteList, sizeof(byteList), true,
                 new HexEncoder(
                     new StringSink(encoded)));
    wstring encoded1(encoded.begin(), encoded.end());
    return encoded1;
}

wstring PrettyPrintString(string str)
{
    // Pretty print a string
    string encoded = "";

    // HexEncoder
    StringSource(str, true,
                 new HexEncoder(
                     new StringSink(encoded)));
    wstring encoded1(encoded.begin(), encoded.end());

    return encoded1;
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

void AES_CBC(wstring wPlain, byte key[], byte iv[], int keyLength, int ivLength)
{
    string plain = wstring_to_utf8(wPlain);
    string cipher, encoded, recovered;
    wstring encodedRecovered(encoded.begin(), encoded.end());
    // Pretty print key
    encoded.clear();
    StringSource(key, keyLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wstring encodedKey(encoded.begin(), encoded.end());
    wcout << "key: " << encodedKey << endl;

    // Pretty print iv
    encoded.clear();
    StringSource(iv, ivLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wstring encodedIV(encoded.begin(), encoded.end());
    wcout << "iv: " << encodedIV << endl;

    try
    {
        wcout << "plain text: " << wPlain << endl;

        CBC_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(plain, true,
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher)) // StreamTransformationFilter
        );                                                                    // StringSource

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
        cerr << e.what() << endl;
        exit(1);
    }

    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wstring encodedCipher(encoded.begin(), encoded.end());
    wcout << "cipher text: " << encodedCipher << endl;

    try
    {
        CBC_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource

#if 0
		StreamTransformationFilter filter(d);
		filter.Put((const byte*)cipher.data(), cipher.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		recovered.resize(ret);
		filter.Get((byte*)recovered.data(), recovered.size());
#endif
        wstring encodedRecovered = utf8_to_wstring(recovered);
        wcout << "recovered text: " << encodedRecovered << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}

void AES_CFB(wstring wPlain, byte key[], byte iv[], int keyLength, int ivLength)
{
    string plain = wstring_to_utf8(wPlain);
    string cipher, encoded, recovered;

    // Pretty print key
    encoded.clear();
    StringSource(key, keyLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    wstring encodedKey(encoded.begin(), encoded.end());
    wcout << "key: " << encodedKey << endl;

    // Pretty print iv
    encoded.clear();
    StringSource(iv, ivLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wstring encodedIV(encoded.begin(), encoded.end());
    wcout << "iv: " << encodedIV << endl;

    try
    {
        wcout << "plain text: " << wPlain << endl;

        CFB_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, keyLength, iv);

        // CFB mode must not use padding. Specifying
        //  a scheme will result in an exception
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

    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wstring encodedCipher(encoded.begin(), encoded.end());
    wcout << "cipher text: " << encodedCipher << endl;

    try
    {
        CFB_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource

        wstring encodedRecovered = utf8_to_wstring(recovered);
        wcout << "recovered text: " << encodedRecovered << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}

void AES_ECB(wstring wPlain, byte key[], int keyLength)
{
    string plain = wstring_to_utf8(wPlain);
    string cipher, encoded, recovered;

    // Pretty print key
    encoded.clear();
    StringSource(key, keyLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wstring encodedKey(encoded.begin(), encoded.end());
    wcout << "key: " << encodedKey << endl;

    try
    {
        wcout << "plain text: " << wPlain << endl;

        ECB_Mode<AES>::Encryption e;
        e.SetKey(key, keyLength);

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

    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wstring encodedCipher(encoded.begin(), encoded.end());
    wcout << "cipher text: " << encodedCipher << endl;

    try
    {
        ECB_Mode<AES>::Decryption d;
        d.SetKey(key, keyLength);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource
        wstring encodedRecovered = utf8_to_wstring(recovered);
        wcout << "recovered text: " << encodedRecovered << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}

void AES_OFB(wstring wPlain, byte key[], byte iv[], int keyLength, int ivLength)
{
    string plain = wstring_to_utf8(wPlain);
    string cipher, encoded, recovered;

    // Pretty print key
    encoded.clear();
    StringSource(key, keyLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wstring encodedKey(encoded.begin(), encoded.end());
    wcout << "key: " << encodedKey << endl;

    // Pretty print iv
    encoded.clear();
    StringSource(iv, ivLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wstring encodedIV(encoded.begin(), encoded.end());
    wcout << "iv: " << encodedIV << endl;

    try
    {
        wcout << "plain text: " << wPlain << endl;

        OFB_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, keyLength, iv);

        // OFB mode must not use padding. Specifying
        //  a scheme will result in an exception
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

    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wstring encodedCipher(encoded.begin(), encoded.end());
    wcout << "cipher text: " << encodedCipher << endl;

    try
    {
        OFB_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, sizeof(key), iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource
        wstring encodedRecovered = utf8_to_wstring(recovered);
        wcout << "recovered text: " << encodedRecovered << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}

void AES_CTR(wstring wPlain, byte key[], byte iv[], int keyLength, int ivLength)
{
    string plain = wstring_to_utf8(wPlain);
    string cipher, encoded, recovered;

    // Pretty print key
    encoded.clear();
    StringSource(key, keyLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wstring encodedKey(encoded.begin(), encoded.end());
    wcout << "key: " << encodedKey << endl;

    // Pretty print iv
    encoded.clear();
    StringSource(iv, ivLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wstring encodedIV(encoded.begin(), encoded.end());
    wcout << "iv: " << encodedIV << endl;

    try
    {
        wcout << "plain text: " << wPlain << endl;

        CTR_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, keyLength, iv);

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

    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wstring encodedCipher(encoded.begin(), encoded.end());
    wcout << "cipher text: " << encodedCipher << endl;

    try
    {
        CTR_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, sizeof(key), iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource
        wstring encodedRecovered = utf8_to_wstring(recovered);
        wcout << "recovered text: " << encodedRecovered << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}

void AES_XTS(wstring wPlain, byte key[], byte iv[], int keyLength, int ivLength)
{
    using namespace CryptoPP;

    string plain = wstring_to_utf8(wPlain);
    std::string cipher, encoded, recovered;

    try
    {
        XTS_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(key, keyLength, iv);

#if 0
        std::cout << "key length: " << enc.DefaultKeyLength() << std::endl;
        std::cout << "key length (min): " << enc.MinKeyLength() << std::endl;
        std::cout << "key length (max): " << enc.MaxKeyLength() << std::endl;
        std::cout << "block size: " << enc.BlockSize() << std::endl;
#endif

        // The StreamTransformationFilter adds padding
        //  as requiredec. ECB and XTS Mode must be padded
        //  to the block size of the cipher.
        StringSource ss(plain, true,
                        new StreamTransformationFilter(enc,
                                                       new StringSink(cipher),
                                                       StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                                     // StringSource
        std::wcout << "plain text: " << wPlain << std::endl;
    }
    catch (const CryptoPP::Exception &ex)
    {
        std::cerr << ex.what() << std::endl;
        exit(1);
    }

    encoded.clear();
    StringSource ss1(key, keyLength, true,
                     new HexEncoder(
                         new StringSink(encoded)) // HexEncoder
    );                                            // StringSource
    wstring encodedKey(encoded.begin(), encoded.end());
    std::wcout << "key: " << encodedKey << std::endl;

    encoded.clear();
    StringSource ss2(iv, ivLength, true,
                     new HexEncoder(
                         new StringSink(encoded)) // HexEncoder
    );                                            // StringSource
    wstring encodedIV(encoded.begin(), encoded.end());
    std::wcout << " iv: " << encodedIV << std::endl;

    // Pretty print cipher text
    encoded.clear();
    StringSource ss3(cipher, true,
                     new HexEncoder(
                         new StringSink(encoded)) // HexEncoder
    );                                            // StringSource
    wstring encodedCipher(encoded.begin(), encoded.end());
    std::wcout << "cipher text: " << encodedCipher << std::endl;

    try
    {
        XTS_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter removes
        //  padding as requiredec.
        StringSource ss(cipher, true,
                        new StreamTransformationFilter(dec,
                                                       new StringSink(recovered),
                                                       StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );

        // StringSource
        wstring encodedRecovered = utf8_to_wstring(recovered);
        wcout << "recovered text: " << encodedRecovered << endl;
    }
    catch (const CryptoPP::Exception &ex)
    {
        std::cerr << ex.what() << std::endl;
        exit(1);
    }
}

void AES_CCM(wstring wPlain, byte key[], byte iv[], int keyLength, int ivLength)
{
    string plain = wstring_to_utf8(wPlain);

    const int TAG_SIZE = 8;

    // Encrypted, with Tag
    string cipher, encoded;

    // Recovered
    string recovered;

    // Pretty print
    encoded.clear();
    StringSource(key, keyLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wstring encodedKey(encoded.begin(), encoded.end());
    wcout << "key: " << encodedKey << endl;

    // Pretty print
    encoded.clear();
    StringSource(iv, ivLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wstring encodedIV(encoded.begin(), encoded.end());
    wcout << " iv: " << encodedIV << endl;

    cout << endl;

    try
    {
        wcout << "plain text: " << wPlain << endl;

        CCM<AES, TAG_SIZE>::Encryption e;
        e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
        e.SpecifyDataLengths(0, plain.size(), 0);

        StringSource(plain, true,
                     new AuthenticatedEncryptionFilter(e,
                                                       new StringSink(cipher)) // AuthenticatedEncryptionFilter
        );                                                                     // StringSource
    }
    catch (CryptoPP::InvalidArgument &e)
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch (CryptoPP::Exception &e)
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }

    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wstring encodedCipher(encoded.begin(), encoded.end());
    wcout << "cipher text: " << encodedCipher << endl;

    try
    {
        CCM<AES, TAG_SIZE>::Decryption d;
        d.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
        d.SpecifyDataLengths(0, cipher.size() - TAG_SIZE, 0);

        AuthenticatedDecryptionFilter df(d,
                                         new StringSink(recovered)); // AuthenticatedDecryptionFilter

        StringSource(cipher, true,
                     new Redirector(df /*, PASS_EVERYTHING */)); // StringSource

        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity
        bool b = df.GetLastResult();
        assert(true == b);

        wstring encodedRecovered = utf8_to_wstring(recovered);
        wcout << "recovered text: " << encodedRecovered << endl;
    }

    catch (CryptoPP::Exception &e)
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
}

void AES_GCM(wstring wPlain, byte key[], byte iv[], int keyLength, int ivLength)
{
    string plain = wstring_to_utf8(wPlain);
    string cipher, encoded, recovered;
    // Pretty print key
    encoded.clear();
    StringSource(key, keyLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wstring encodedKey(encoded.begin(), encoded.end());
    wcout << "key: " << encodedKey << endl;

    // Pretty print iv
    encoded.clear();
    StringSource(iv, ivLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wstring encodedIV(encoded.begin(), encoded.end());
    wcout << "iv: " << encodedIV << endl;

    try
    {
        wcout << "plain text: " << wPlain << endl;

        GCM<AES>::Encryption e;
        e.SetKeyWithIV(key, keyLength, iv, ivLength);

        StringSource(plain, true,
                     new AuthenticatedEncryptionFilter(e,
                                                       new StringSink(cipher)) // StreamTransformationFilter
        );                                                                     // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wstring encodedCipher(encoded.begin(), encoded.end());
    wcout << "cipher text: " << encodedCipher << endl;

    try
    {
        GCM<AES>::Decryption d;
        d.SetKeyWithIV(key, keyLength, iv, ivLength);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
                       new AuthenticatedDecryptionFilter(d,
                                                         new StringSink(recovered)) // StreamTransformationFilter
        );                                                                          // StringSource

        wstring encodedRecovered = utf8_to_wstring(recovered);
        wcout << "recovered text: " << encodedRecovered << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}

void ChooseModeKeyAndIV(int &mode)
{
    cout << "(1)Key and iv is random\n";
    cout << "(2)Key and iv from screen\n";
    cout << "(3)key and iv from file\n";
    cin >> mode;
    cin.ignore();
}

void ModeExecute()
{
    int keyAndIVMode, mode;
    int keyLength, ivLength;
    wstring wPlain;
    wstring wkey, wiv;
    string keyString, ivString;
    CryptoPP::byte key[16];
    CryptoPP::byte iv[32];

    wcout << "(1)Key and iv is random\n";
    wcout << "(2)Key and iv from screen\n";
    wcout << "(3)key and iv from file\n";
    wcin >> keyAndIVMode;
    wcin.ignore();

    if (keyAndIVMode == 1)
    {
        CreateRandomKeyIV(key, iv);
        keyLength = sizeof(key);
        ivLength = sizeof(iv);
    }

    else if (keyAndIVMode == 2)
    {

        CryptoPP::byte key[100];
        CryptoPP::byte iv[100];

        wcout << L"Enter key(16 bytes): ";
        fflush(stdin);
        wcin.ignore();
        getline(wcin, wkey);
        keyString = wstring_to_utf8(wkey);
        keyLength = keyString.length();

        wcout << L"Enter iv (16 bytes):";
        fflush(stdin);
        wcin.ignore();
        getline(wcin, wiv);
        ivString = wstring_to_utf8(wiv);
        ivLength = ivString.length();

        StringSource ss(keyString, false);
        CryptoPP::ArraySink copykey(key, sizeof(key));
        ss.Detach(new Redirector(copykey));
        ss.Pump(16);

        StringSource s1(ivString, false);
        CryptoPP::ArraySink copyiv(iv, sizeof(iv));
        s1.Detach(new Redirector(copyiv));
        s1.Pump(16);
        wcout << endl;
    }

    else
    {

        //Write key to file AES_key.key
        StringSource s2(iv, sizeof(iv), true, new FileSink("AES_iv.key"));
        /* Reading key from file*/
        FileSource fs("AES_iv.key", false);
        /*Create space  for key*/
        CryptoPP::ArraySink copyiv2(iv, sizeof(iv));
        /*Copy data from AES_key.key  to  key */
        fs.Detach(new Redirector(copyiv2));
        fs.Pump(16); // Pump first 16 bytes
        ivLength = 16;

        //Write key to file AES_key.key
        StringSource s3(iv, sizeof(iv), true, new FileSink("AES_iv.key"));
        /* Reading key from file*/
        FileSource fs1("AES_iv.key", false);
        /*Create space  for key*/
        CryptoPP::ArraySink copyiv3(iv, sizeof(iv));
        /*Copy data from AES_key.key  to  key */
        fs1.Detach(new Redirector(copyiv3));
        fs1.Pump(16); // Pump first 16 bytes
        ivLength = 16;
    }
    //wcin.ignore();
    wcout << "(1)CBC (2)CFB (3)ECB (4)OFB (5)CTR (6)XTS (7)CCM (8)GCM: ";
    wcin >> mode;
    wcin.ignore();

    // Get the input
    wcout << "Enter input: ";
    getline(wcin, wPlain);

    switch (mode)
    {
    case 1:
        cout << "AES Mode CBC\n";
        AES_CBC(wPlain, key, iv, keyLength, ivLength);
        break;

    case 2:
        cout << "AES Mode CFB\n";
        AES_CFB(wPlain, key, iv, keyLength, ivLength);
        break;

    case 3:
        cout << "AES Mode ECB\n";
        AES_ECB(wPlain, key, keyLength);
        break;

    case 4:
        cout << "AES Mode OFB\n";
        AES_OFB(wPlain, key, iv, keyLength, ivLength);
        break;

    case 5:
        cout << "AES Mode CTR\n";
        AES_CTR(wPlain, key, iv, keyLength, ivLength);
        break;
    case 6:
        cout << "AES Mode XTS\n";
        AES_XTS(wPlain, key, iv, keyLength, ivLength);
        break;
    case 7:
        cout << "AES Mode CCM\n";
        AES_CCM(wPlain, key, iv, keyLength, ivLength);
    case 8:
        cout << "AES Mode GCM\n";
        AES_GCM(wPlain, key, iv, keyLength, ivLength);
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
    //std::wcout.imbue(std::locale("en_US.utf8"));
    ModeExecute();

    return 0;
}