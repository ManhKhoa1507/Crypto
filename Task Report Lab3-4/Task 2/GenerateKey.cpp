#include <assert.h>

#include <iostream>
using std::cout;
using std::endl;

#include <string>
using std::string;

#include "cryptopp/osrng.h"
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
bool GeneratePrivateKey(const OID &oid, ECDSA<ECP, SHA1>::PrivateKey &key);
bool GeneratePublicKey(const ECDSA<ECP, SHA1>::PrivateKey &privateKey, ECDSA<ECP, SHA1>::PublicKey &publicKey);
void SavePrivateKey(const string &filename, const ECDSA<ECP, SHA1>::PrivateKey &key);
void SavePublicKey(const string &filename, const ECDSA<ECP, SHA1>::PublicKey &key);
void LoadPrivateKey(const string &filename, ECDSA<ECP, SHA1>::PrivateKey &key);
void LoadPublicKey(const string &filename, ECDSA<ECP, SHA1>::PublicKey &key);

void PrintDomainParameters(const ECDSA<ECP, SHA1>::PrivateKey &key);
void PrintDomainParameters(const ECDSA<ECP, SHA1>::PublicKey &key);
void PrintDomainParameters(const DL_GroupParameters_EC<ECP> &params);
void PrintPrivateKey(const ECDSA<ECP, SHA1>::PrivateKey &key);
void PrintPublicKey(const ECDSA<ECP, SHA1>::PublicKey &key);

int main(int argc, char *argv[])
{
    // Scratch result
    cout << "Creating key";

    // Private and Public keys
    ECDSA<ECP, SHA1>::PrivateKey privateKey;
    ECDSA<ECP, SHA1>::PublicKey publicKey;

    // Generate Keys
    GeneratePrivateKey(CryptoPP::ASN1::secp256r1(), privateKey);
    GeneratePublicKey(privateKey, publicKey);

    // Print Domain Parameters and Keys
    PrintDomainParameters(publicKey);
    PrintPrivateKey(privateKey);
    PrintPublicKey(publicKey);

    // Save key in PKCS#9 and X.509 format
    SavePrivateKey("ec.private.key", privateKey);
    SavePublicKey("ec.public.key", publicKey);

    // // Pretty print signature
    // AutoSeededRandomPool prng;
    // // Load secret key
    // // LoadPrivateKey( "ec.private.key", privateKey);

    // // Print parameters
    // cout << std::hex << "Prime number p=" << privateKey.GetGroupParameters().GetCurve().GetField().GetModulus()<<endl;
    // cout << "Secret key d:" << std::hex << privateKey.GetPrivateExponent() << endl;

    // // Public keys:
    // privateKey.MakePublicKey(publicKey);
    // cout << "Public key Q=(Qx,Qy):" << endl;
    // cout << "Qx=" << std::hex << publicKey.GetPublicElement().x << endl;
    // cout << "Qy=" << std::hex << publicKey.GetPublicElement().y << endl;
    return 0;
}

bool GeneratePrivateKey(const OID &oid, ECDSA<ECP, SHA1>::PrivateKey &key)
{
    AutoSeededRandomPool prng;

    key.Initialize(prng, oid);
    assert(key.Validate(prng, 3));

    return key.Validate(prng, 3);
}

bool GeneratePublicKey(const ECDSA<ECP, SHA1>::PrivateKey &privateKey, ECDSA<ECP, SHA1>::PublicKey &publicKey)
{
    AutoSeededRandomPool prng;

    // Sanity check
    assert(privateKey.Validate(prng, 3));

    privateKey.MakePublicKey(publicKey);
    assert(publicKey.Validate(prng, 3));

    return publicKey.Validate(prng, 3);
}

void PrintDomainParameters(const ECDSA<ECP, SHA1>::PrivateKey &key)
{
    PrintDomainParameters(key.GetGroupParameters());
}

void PrintDomainParameters(const ECDSA<ECP, SHA1>::PublicKey &key)
{
    PrintDomainParameters(key.GetGroupParameters());
}

void PrintDomainParameters(const DL_GroupParameters_EC<ECP> &params)
{
    cout << endl;

    cout << "Modulus:" << endl;
    cout << " " << params.GetCurve().GetField().GetModulus() << endl;

    cout << "Coefficient A:" << endl;
    cout << " " << params.GetCurve().GetA() << endl;

    cout << "Coefficient B:" << endl;
    cout << " " << params.GetCurve().GetB() << endl;

    cout << "Base Point:" << endl;
    cout << " X: " << params.GetSubgroupGenerator().x << endl;
    cout << " Y: " << params.GetSubgroupGenerator().y << endl;

    cout << "Subgroup Order:" << endl;
    cout << " " << params.GetSubgroupOrder() << endl;

    cout << "Cofactor:" << endl;
    cout << " " << params.GetCofactor() << endl;
}

void PrintPrivateKey(const ECDSA<ECP, SHA1>::PrivateKey &key)
{
    cout << endl;
    cout << "Private Exponent:" << endl;
    cout << " " << key.GetPrivateExponent() << endl;
}

void PrintPublicKey(const ECDSA<ECP, SHA1>::PublicKey &key)
{
    cout << endl;
    cout << "Public Element:" << endl;
    cout << " X: " << key.GetPublicElement().x << endl;
    cout << " Y: " << key.GetPublicElement().y << endl;
}

void SavePrivateKey(const string &filename, const ECDSA<ECP, SHA1>::PrivateKey &key)
{
    key.Save(FileSink(filename.c_str(), true /*binary*/).Ref());
}

void SavePublicKey(const string &filename, const ECDSA<ECP, SHA1>::PublicKey &key)
{
    key.Save(FileSink(filename.c_str(), true /*binary*/).Ref());
}

void LoadPrivateKey(const string &filename, ECDSA<ECP, SHA1>::PrivateKey &key)
{
    key.Load(FileSource(filename.c_str(), true /*pump all*/).Ref());
}

void LoadPublicKey(const string &filename, ECDSA<ECP, SHA1>::PublicKey &key)
{
    key.Load(FileSource(filename.c_str(), true /*pump all*/).Ref());
}