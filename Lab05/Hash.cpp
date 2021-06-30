#include <fcntl.h>
#include <locale>
#include <ctime>
#include <codecvt>

#include <iostream>
using std::cerr;
using std::endl;
using std::wcin;
using std::wcout;

#include <string>
using std::string;
using std::wstring;

#include <cryptopp/sha.h>
using CryptoPP::SHA224;
using CryptoPP::SHA256;
using CryptoPP::SHA384;
using CryptoPP::SHA512;

#include <cryptopp/shake.h>
using CryptoPP::SHAKE128;
using CryptoPP::SHAKE256;

#include <cryptopp/sha3.h>
using CryptoPP::SHA3_224;
using CryptoPP::SHA3_256;
using CryptoPP::SHA3_384;
using CryptoPP::SHA3_512;

#include <cryptopp/hex.h>
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include <cryptopp/filters.h>
using CryptoPP::HashFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include <cryptopp/files.h>
using CryptoPP::FileSink;
using CryptoPP::FileSource;

string wstring_to_string(const wstring &str_in);
wstring string_to_wstring(const string &str_in);

string LoadMessageFromFile(string path);

double SHA224_hashing(string sMessage, string &hDigest);
double SHA256_hashing(string sMessage, string &hDigest);
double SHA384_hashing(string sMessage, string &hDigest);
double SHA512_hashing(string sMessage, string &hDigest);

double SHA3_224_hashing(string sMessage, string &hDigest);
double SHA3_256_hashing(string sMessage, string &hDigest);
double SHA3_384_hashing(string sMessage, string &hDigest);
double SHA3_512_hashing(string sMessage, string &hDigest);

double SHAKE128_hashing(string sMessage, string &hDigest, int d);
double SHAKE256_hashing(string sMessage, string &hDigest, int d);

int main()
{

#ifdef __linux__
    setlocale(LC_ALL, "");
#elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif

    wstring wMessage, wDigest, wPath;
    string sMessage, hDigest, sPath;
    double result;
    double total = 0;
    bool loop = false;

    int choice, d;

    wcout << L"--- Secure Hash Algorithm ---\n"
          << L"Please choose your mode:\n"
          << L"(1)From file\t"
          << L"(2)From keyboard\n";
    wcin >> choice;
    wcin.ignore();

    switch (choice)
    {
    case 1:

        wcout << L"Specify path to message file: ";
        getline(wcin, wPath);

        sPath = wstring_to_string(wPath);
        FileSource(sPath.c_str(), true, new StringSink(sMessage));

        break;

    case 2:
        wcout << L"Input message: ";
        getline(wcin, wMessage);
        sMessage = wstring_to_string(wMessage);

        break;

    default:
        wcout << L"Invalid choice.\n";
        exit(1);
    }

    wcout << "\nPlease choose your mode: \n";
    wcout << L"(1)SHA-224\t(6)SHA3-256\n"
          << L"(2)SHA-256\t(7)SHA3-384\n"
          << L"(3)SHA-384\t(8)SHA3-512\n"
          << L"(4)SHA-512\t(9)SHAKE-128\n"
          << L"(5)SHA3-224\t(10)SHAKE-256\n"
          << L"> ";
    wcin >> choice;

    switch (choice)
    {
    case 1:
        for (int i = 0; i < 10000; i++)
        {
            hDigest.clear();
            total += SHA224_hashing(sMessage, hDigest);
        }
        break;

    case 2:
        for (int i = 0; i < 10000; i++)
        {
            hDigest.clear();
            total += SHA256_hashing(sMessage, hDigest);
        }
        break;

    case 3:
        for (int i = 0; i < 10000; i++)
        {
            hDigest.clear();
            total += SHA384_hashing(sMessage, hDigest);
        }
        break;

    case 4:
        for (int i = 0; i < 10000; i++)
        {
            hDigest.clear();
            total += SHA512_hashing(sMessage, hDigest);
        }
        break;

    case 5:
        for (int i = 0; i < 10000; i++)
        {
            hDigest.clear();
            total += SHA3_224_hashing(sMessage, hDigest);
        }
        break;

    case 6:
        for (int i = 0; i < 10000; i++)
        {
            hDigest.clear();
            total += SHA3_256_hashing(sMessage, hDigest);
        }
        break;

    case 7:
        for (int i = 0; i < 10000; i++)
        {
            hDigest.clear();
            total += SHA3_384_hashing(sMessage, hDigest);
        }
        break;

    case 8:
        for (int i = 0; i < 10000; i++)
        {
            hDigest.clear();
            total += SHA3_512_hashing(sMessage, hDigest);
        }
        break;

    case 9:
        do
        {
            if (loop != true)

                wcout << L"\n"
                      << L"Enter number of output bytes: ";
            wcin >> d;

            loop = false;

            if (d <= 0)
            {

                wcout << L"Invalid length.\n\n";
                loop = true;
            }
        } while (loop);

        for (int i = 0; i < 10000; i++)
        {
            hDigest.clear();
            total += SHAKE128_hashing(sMessage, hDigest, d);
        }
        break;

    case 10:
        do
        {
            if (loop != true)

                wcout << L"\n"
                      << L"Enter number of output bytes: ";
            wcin >> d;

            loop = false;

            if (d <= 0)
            {

                wcout << L"Invalid length.\n\n";
                loop = true;
            }
        } while (loop);

        for (int i = 0; i < 10000; i++)
        {
            hDigest.clear();
            total += SHAKE256_hashing(sMessage, hDigest, d);
        }
        break;

    default:

        wcout << L"Invalid choice.\n";
        exit(1);
    }

    result = total / 10000;

    wDigest = string_to_wstring(hDigest);
    wMessage = string_to_wstring(sMessage);

    wcout << L"Message: " << wMessage << endl;
    wcout << L"Digest: " << wDigest << endl;

    wcout << L"\nExecution time: " << result << " ms" << endl;
    wcout << L"Total time for 10,000 rounds: " << total << " ms"
          << "\n\n";
}

string wstring_to_string(const wstring &str_in)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> str_out;
    return str_out.to_bytes(str_in);
}

wstring string_to_wstring(const string &str_in)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> str_out;
    return str_out.from_bytes(str_in);
}

string LoadMessageFromFile(string path)
{
    string sMessage;
    FileSource(path.c_str(), true, new StringSink(sMessage));
    return sMessage;
}

/* SHA-224*/
double SHA224_hashing(string sMessage, string &hDigest)
{
    SHA224 hash;

    double etime;
    int start_timer = clock();

    StringSource(sMessage, true,
                 new HashFilter(hash,
                                new HexEncoder(new StringSink(hDigest))));

    int stop_timer = clock();

    etime = (stop_timer - start_timer) / double(CLOCKS_PER_SEC) * 1000;

    return etime;
}

/* SHA-256 */
double SHA256_hashing(string sMessage, string &hDigest)
{
    SHA256 hash;

    double etime;
    int start_timer = clock();

    StringSource(sMessage, true,
                 new HashFilter(hash,
                                new HexEncoder(new StringSink(hDigest))));

    int stop_timer = clock();

    etime = (stop_timer - start_timer) / double(CLOCKS_PER_SEC) * 1000;

    return etime;
}

/* SHA-384 */
double SHA384_hashing(string sMessage, string &hDigest)
{
    SHA384 hash;

    double etime;
    int start_timer = clock();

    StringSource(sMessage, true,
                 new HashFilter(hash,
                                new HexEncoder(new StringSink(hDigest))));

    int stop_timer = clock();

    etime = (stop_timer - start_timer) / double(CLOCKS_PER_SEC) * 1000;

    return etime;
}

/* SHA-512 */
double SHA512_hashing(string sMessage, string &hDigest)
{
    SHA512 hash;

    double etime;
    int start_timer = clock();

    StringSource(sMessage, true,
                 new HashFilter(hash,
                                new HexEncoder(new StringSink(hDigest))));

    int stop_timer = clock();

    etime = (stop_timer - start_timer) / double(CLOCKS_PER_SEC) * 1000;

    return etime;
}

/* SHA3-224 */
double SHA3_224_hashing(string sMessage, string &hDigest)
{
    SHA3_224 hash;

    double etime;
    int start_timer = clock();

    StringSource(sMessage, true,
                 new HashFilter(hash,
                                new HexEncoder(new StringSink(hDigest))));

    int stop_timer = clock();

    etime = (stop_timer - start_timer) / double(CLOCKS_PER_SEC) * 1000;

    return etime;
}

/* SHA3-256 */
double SHA3_256_hashing(string sMessage, string &hDigest)
{
    SHA3_256 hash;

    double etime;
    int start_timer = clock();

    StringSource(sMessage, true,
                 new HashFilter(hash,
                                new HexEncoder(new StringSink(hDigest))));

    int stop_timer = clock();

    etime = (stop_timer - start_timer) / double(CLOCKS_PER_SEC) * 1000;

    return etime;
}

/* SHA3-384 */
double SHA3_384_hashing(string sMessage, string &hDigest)
{
    SHA3_384 hash;

    double etime;
    int start_timer = clock();

    StringSource(sMessage, true,
                 new HashFilter(hash,
                                new HexEncoder(new StringSink(hDigest))));

    int stop_timer = clock();

    etime = (stop_timer - start_timer) / double(CLOCKS_PER_SEC) * 1000;

    return etime;
}

/* SHA3-512 */
double SHA3_512_hashing(string sMessage, string &hDigest)
{
    SHA3_512 hash;

    double etime;
    int start_timer = clock();

    StringSource(sMessage, true,
                 new HashFilter(hash,
                                new HexEncoder(new StringSink(hDigest))));

    int stop_timer = clock();

    etime = (stop_timer - start_timer) / double(CLOCKS_PER_SEC) * 1000;

    return etime;
}

double SHAKE128_hashing(string sMessage, string &hDigest, int d)
{
    SHAKE128 hash(d);

    double etime;
    int start_timer = clock();

    StringSource(sMessage, true,
                 new HashFilter(hash,
                                new HexEncoder(new StringSink(hDigest))));

    int stop_timer = clock();

    etime = (stop_timer - start_timer) / double(CLOCKS_PER_SEC) * 1000;

    return etime;
}

double SHAKE256_hashing(string sMessage, string &hDigest, int d)
{
    SHAKE256 hash(d);

    double etime;
    int start_timer = clock();

    StringSource(sMessage, true,
                 new HashFilter(hash,
                                new HexEncoder(new StringSink(hDigest))));

    int stop_timer = clock();

    etime = (stop_timer - start_timer) / double(CLOCKS_PER_SEC) * 1000;

    return etime;
}
///////////////////////////////////////////////////////////////////////////////////////