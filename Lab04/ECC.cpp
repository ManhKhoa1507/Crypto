//  Defines the entry point for the console application
/*ECC parameters p,a,b, P (or G), n, h where p=h.n*/

/* Source, Sink */
#include "cryptopp/filters.h"

#include <ctime>
#include <iostream>
#include <string>
using namespace std;

/* Randomly generator*/
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

/* Integer arithmatics*/
#include <cryptopp/integer.h>
using CryptoPP::Integer;
#include <cryptopp/nbtheory.h>
using CryptoPP::ModularSquareRoot;

#include <cryptopp/ecp.h>
#include <cryptopp/eccrypto.h>
using CryptoPP::ECP;    // Prime field p
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::ECIES;
using CryptoPP::ECPPoint;
using CryptoPP::DL_GroupPrecomputation;
using CryptoPP::DL_FixedBasePrecomputation;

#include <cryptopp/pubkey.h>
using CryptoPP::PublicKey;
using CryptoPP::PrivateKey;

/* standard curves*/
#include <cryptopp/asn.h>
#include <cryptopp/oids.h> // 
namespace ASN1 = CryptoPP::ASN1;
using CryptoPP::OID;



int main(int argc, char *argv[])
{

    try
    {
        CryptoPP::ECIES<ECC_ALGORITHM>::PrivateKey privateKey;
        CryptoPP::ECIES<ECC_ALGORITHM>::PublicKey publicKey;
        CryptoPP::AutoSeededRandomPool rng;

        // Key Generation
        privateKey.Initialize(rng, ECC_CURVE);
        privateKey.MakePublicKey(publicKey);

        // Key Validation
        if (false == privateKey.Validate(rng, 3))
        {
            throw runtime_error("Private key validation failed");
        }

        if (false == publicKey.Validate(rng, 3))
        {
            throw runtime_error("Public key validation failed");
        }

        // Encryptor and Decryptor
        CryptoPP::ECIES<ECC_ALGORITHM>::Encryptor Encryptor(publicKey);
        CryptoPP::ECIES<ECC_ALGORITHM>::Decryptor Decryptor(privateKey);

        // Message
        string plainText = "Yoda said, Do or do not. There is no try.";
        size_t plainTextLength = plainText.length() + 1;

        cout << "Plain text: " << plainText << endl;
        cout << "Plain text length is " << plainTextLength << " (including the trailing NULL)" << endl;

        // Size
        size_t cipherTextLength = Encryptor.CiphertextLength(plainTextLength);

        if (0 == cipherTextLength)
        {
            throw runtime_error("cipherTextLength is not valid");
        }

        cout << "Cipher text length is ";
        cout << cipherTextLength << endl;

        // Encryption buffer
        byte *cipherText = new byte[cipherTextLength];
        if (NULL == cipherText)
        {
            throw runtime_error("Cipher text allocation failure");
        }

        memset(cipherText, 0xFB, cipherTextLength);

        // Encryption
        Encryptor.Encrypt(rng, reinterpret_cast<const byte *>(plainText.data()), plainTextLength, cipherText);

        // Size
        size_t recoveredTextLength = Decryptor.MaxPlaintextLength(cipherTextLength);
        if (0 == recoveredTextLength)
        {
            throw runtime_error("recoveredTextLength is not valid");
        }

        // Decryption Buffer
        char *recoveredText = new char[recoveredTextLength];
        if (NULL == recoveredText)
        {
            throw runtime_error("recoveredText allocation failure");
        }

        memset(recoveredText, 0xFB, recoveredTextLength);

        // Decryption
        Decryptor.Decrypt(rng, cipherText, cipherTextLength, reinterpret_cast<byte *>(recoveredText));

        cout << "Recovered text: " << recoveredText << endl;
        cout << "Recovered text length is " << recoveredTextLength << endl;

        // Cleanup
        if (NULL != cipherText)
        {
            delete[] cipherText;
        }

        if (NULL != recoveredText)
        {
            delete[] recoveredText;
        }
    }

    catch (CryptoPP::Exception &e)
    {
        cerr << "Crypto++ error: " << e.what() << endl;
        return -3;
    }

    catch (runtime_error &e)
    {
        cerr << "Runtime error: " << e.what() << endl;
        return -2;
    }

    catch (exception &e)
    {
        cerr << "Error: " << e.what() << endl;
        return -1;
    }

    return 0;
}
