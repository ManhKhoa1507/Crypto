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

#include "cryptopp/des.h"
using CryptoPP::DES;
using CryptoPP::DES_EDE2;
using CryptoPP::DES_EDE3;

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

void DES_CBC(wstring wPlain, byte key[], byte iv[], int keyLength, int ivLength)
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

        CBC_Mode<DES>::Encryption e;
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
    wcout << "cipher: " << encodedCipher << endl;

    try
    {
        CBC_Mode<DES>::Decryption d;
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

void DES_CBC_Time(wstring wPlain, byte key[], byte iv[], int keyLength, int ivLength)
{
    string plain = wstring_to_utf8(wPlain);
    string cipher, encoded, recovered;

    try
    {
        CBC_Mode<DES>::Encryption e;
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

    try
    {
        CBC_Mode<DES>::Decryption d;
        d.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}

void DES2_CBC(wstring wPlain, byte key[], byte iv[], int keyLength, int ivLength)
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

        CBC_Mode<DES_EDE2>::Encryption e;
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
    wcout << "cipher: " << encodedCipher << endl;

    try
    {
        CBC_Mode<DES_EDE2>::Decryption d;
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

void DES2_CBC_Time(wstring wPlain, byte key[], byte iv[], int keyLength, int ivLength)
{
    string plain = wstring_to_utf8(wPlain);
    string cipher, encoded, recovered;

    try
    {

        CBC_Mode<DES_EDE2>::Encryption e;
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

    try
    {
        CBC_Mode<DES_EDE2>::Decryption d;
        d.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}

void DES3_CBC(wstring wPlain, byte key[], byte iv[], int keyLength, int ivLength)
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

        CBC_Mode<DES_EDE3>::Encryption e;
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
    wcout << "key: " << encodedCipher << endl;

    try
    {
        CBC_Mode<DES_EDE3>::Decryption d;
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

void DES3_CBC_Time(wstring wPlain, byte key[], byte iv[], int keyLength, int ivLength)
{
    string plain = wstring_to_utf8(wPlain);
    string cipher, encoded, recovered;
   
    try
    {

        CBC_Mode<DES_EDE3>::Encryption e;
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

    try
    {
        CBC_Mode<DES_EDE3>::Decryption d;
        d.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource
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

void DisplayResult(double total)
{
    // Display result (cipherText, total time to hash 10000 rounds and Execution time)
    wcout << "\nTotal time for 10.000 rounds: " << total << " ms" << endl;
    wcout << "\nExecution time: " << total / 10000 << " ms" << endl
          << endl;
}

double DES_CBC_Time_Cal(wstring wPlain, byte key[], byte iv[], int keyLength, int ivLength)
{
    int start_s = clock();

    DES_CBC_Time(wPlain, key, iv, keyLength, ivLength);

    int stop_s = clock();
    double etime = (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000;
    return etime;
}

double DES2_CBC_Time_Cal(wstring wPlain, byte key[], byte iv[], int keyLength, int ivLength)
{
    int start_s = clock();

    DES2_CBC_Time(wPlain, key, iv, keyLength, ivLength);

    int stop_s = clock();
    double etime = (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000;
    return etime;
}

double DES3_CBC_Time_Cal(wstring wPlain, byte key[], byte iv[], int keyLength, int ivLength)
{
    int start_s = clock();

    DES3_CBC_Time(wPlain, key, iv, keyLength, ivLength);

    int stop_s = clock();
    double etime = (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000;
    return etime;
}

void ModeExecute()
{
    int keyAndIVMode, mode;
    int keyLength, ivLength;
    int a = 0;
    double total, result = 0;
    wstring wPlain;
    wstring wkey, wiv;
    string keyString, ivString;

    //wcin.ignore();
    wcout << "(1)DES_CBC (2)2TDEA_CBC (3)3TDEA_CBC: ";
    wcin >> mode;
    wcin.ignore();

    // Get the input
    wcout << "Enter input: ";
    getline(wcin, wPlain);

    if (mode == 1)
    {
        CryptoPP::byte key[DES::DEFAULT_KEYLENGTH];
        CryptoPP::byte iv[DES::BLOCKSIZE];

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

            wcout << L"Enter key(8 bytes): ";
            fflush(stdin);
            wcin.ignore();
            getline(wcin, wkey);
            keyString = wstring_to_utf8(wkey);
            keyLength = keyString.length();

            wcout << L"Enter iv (8 bytes):";
            fflush(stdin);
            wcin.ignore();
            getline(wcin, wiv);
            ivString = wstring_to_utf8(wiv);
            ivLength = ivString.length();

            StringSource ss(keyString, false);
            CryptoPP::ArraySink copykey(key, sizeof(key));
            ss.Detach(new Redirector(copykey));
            ss.Pump(8);

            StringSource s1(ivString, false);
            CryptoPP::ArraySink copyiv(iv, sizeof(iv));
            s1.Detach(new Redirector(copyiv));
            s1.Pump(8);
            wcout << endl;
        }

        else
        {
            //Write key to file AES_key.key
            StringSource s2(iv, sizeof(iv), true, new FileSink("DES_iv.key"));
            /* Reading key from file*/
            FileSource fs("DES_iv.key", false);
            /*Create space  for key*/
            CryptoPP::ArraySink copyiv2(iv, sizeof(iv));
            /*Copy data from AES_key.key  to  key */
            fs.Detach(new Redirector(copyiv2));
            fs.Pump(8); // Pump first 16 bytes
            ivLength = 8;

            //Write key to file AES_key.key
            StringSource s3(iv, sizeof(iv), true, new FileSink("DES_iv.key"));
            /* Reading key from file*/
            FileSource fs1("DES_iv.key", false);
            /*Create space  for key*/
            CryptoPP::ArraySink copyiv3(iv, sizeof(iv));
            /*Copy data from AES_key.key  to  key */
            fs1.Detach(new Redirector(copyiv3));
            fs1.Pump(8); // Pump first 16 bytes
            ivLength = 8;
        }
        wcout << "DES Mode CBC\n";
        DES_CBC(wPlain, key, iv, keyLength, ivLength);

        while (a < 10000)
        {
            total += DES_CBC_Time_Cal(wPlain, key, iv, keyLength, ivLength);
            a++;
        }
        DisplayResult(total);
    }

    else if (mode == 2)
    {
        CryptoPP::byte key[DES_EDE2::DEFAULT_KEYLENGTH];
        CryptoPP::byte iv[DES_EDE2::BLOCKSIZE];

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

            CryptoPP::byte key[DES_EDE2::DEFAULT_KEYLENGTH];
            CryptoPP::byte iv[DES_EDE2::BLOCKSIZE];

            wcout << L"Enter key(16 bytes): ";
            fflush(stdin);
            wcin.ignore();
            getline(wcin, wkey);
            keyString = wstring_to_utf8(wkey);
            keyLength = keyString.length();

            wcout << L"Enter iv (16 bytes): ";
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
            StringSource s2(iv, sizeof(iv), true, new FileSink("DES_iv.key"));
            /* Reading key from file*/
            FileSource fs("DES_iv.key", false);
            /*Create space  for key*/
            CryptoPP::ArraySink copyiv2(iv, sizeof(iv));
            /*Copy data from AES_key.key  to  key */
            fs.Detach(new Redirector(copyiv2));
            fs.Pump(16); // Pump first 16 bytes
            ivLength = 16;

            //Write key to file AES_key.key
            StringSource s3(iv, sizeof(iv), true, new FileSink("DES_iv.key"));
            /* Reading key from file*/
            FileSource fs1("DES_iv.key", false);
            /*Create space  for key*/
            CryptoPP::ArraySink copyiv3(iv, sizeof(iv));
            /*Copy data from AES_key.key  to  key */
            fs1.Detach(new Redirector(copyiv3));
            fs1.Pump(16); // Pump first 16 bytes
            ivLength = 16;
        }
        wcout << "2DES Mode CBC\n";
        DES2_CBC(wPlain, key, iv, keyLength, ivLength);

        while (a < 10000)
        {
            total += DES2_CBC_Time_Cal(wPlain, key, iv, keyLength, ivLength);
            a++;
        }
        DisplayResult(total);
    }
    else if(mode == 3)
    {
        CryptoPP::byte key[DES_EDE3::DEFAULT_KEYLENGTH];
        CryptoPP::byte iv[DES_EDE3::BLOCKSIZE];

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

            CryptoPP::byte key[DES_EDE3::DEFAULT_KEYLENGTH];
            CryptoPP::byte iv[DES_EDE3::BLOCKSIZE];

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
            StringSource s2(iv, sizeof(iv), true, new FileSink("DES_iv.key"));
            /* Reading key from file*/
            FileSource fs("DES_iv.key", false);
            /*Create space  for key*/
            CryptoPP::ArraySink copyiv2(iv, sizeof(iv));
            /*Copy data from AES_key.key  to  key */
            fs.Detach(new Redirector(copyiv2));
            fs.Pump(16); // Pump first 16 bytes
            ivLength = 16;

            //Write key to file AES_key.key
            StringSource s3(iv, sizeof(iv), true, new FileSink("DES_iv.key"));
            /* Reading key from file*/
            FileSource fs1("DES_iv.key", false);
            /*Create space  for key*/
            CryptoPP::ArraySink copyiv3(iv, sizeof(iv));
            /*Copy data from AES_key.key  to  key */
            fs1.Detach(new Redirector(copyiv3));
            fs1.Pump(16); // Pump first 16 bytes
            ivLength = 16;
        }
        wcout << "3DES Mode CBC\n";
        DES3_CBC(wPlain, key, iv, keyLength, ivLength);

        while (a < 10000)
        {
            total += DES3_CBC_Time_Cal(wPlain, key, iv, keyLength, ivLength);
            a++;
        }
        DisplayResult(total);
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