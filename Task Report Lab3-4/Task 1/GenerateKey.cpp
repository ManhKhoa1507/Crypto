#include <iostream>
using std::cerr;
using std::cout;
using std::endl;

#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;

#include "cryptopp/queue.h"
using CryptoPP::ByteQueue;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/dsa.h"
using CryptoPP::DSA;

#include "cryptopp/rsa.h"
using CryptoPP::RSA;

#include "cryptopp/base64.h"
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;

#include "cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

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

int main(int argc, char **argv)
{
    std::ios_base::sync_with_stdio(false);

#ifdef __linux__
    setlocale(LC_ALL, "");
#elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif

    AutoSeededRandomPool rnd;

    try
    {
        RSA::PrivateKey rsaPrivate;
        rsaPrivate.GenerateRandomWithKeySize(rnd, 3072);

        RSA::PublicKey rsaPublic(rsaPrivate);

        SaveKey(rsaPrivate, "rsa-private.key");
        SaveKey(rsaPublic, "rsa-public.key");

        cout << "Successfully generated and saved RSA and DSA keys" << endl;
    }

    catch (CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        return -2;
    }

    catch (std::exception &e)
    {
        cerr << e.what() << endl;
        return -1;
    }

    return 0;
}
