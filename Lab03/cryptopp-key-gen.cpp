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

void Save(const string &filename, const BufferedTransformation &bt)
{
	FileSink file(filename.c_str());

	bt.CopyTo(file);
	file.MessageEnd();
}

void SavePrivateKey(const string &filename, const PrivateKey &key)
{
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void SavePublicKey(const string &filename, const PublicKey &key)
{
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void SaveBase64(const string &filename, const BufferedTransformation &bt)
{
	Base64Encoder encoder;

	bt.CopyTo(encoder);
	encoder.MessageEnd();

	Save(filename, encoder);
}

void SaveBase64PrivateKey(const string &filename, const PrivateKey &key)
{
	ByteQueue queue;
	key.Save(queue);

	SaveBase64(filename, queue);
}

void SaveBase64PublicKey(const string &filename, const PublicKey &key)
{
	ByteQueue queue;
	key.Save(queue);

	SaveBase64(filename, queue);
}

void Load(const string &filename, BufferedTransformation &bt)
{
	FileSource file(filename.c_str(), true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();
}

void LoadPrivateKey(const string &filename, PrivateKey &key)
{
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);
}

void LoadPublicKey(const string &filename, PublicKey &key)
{
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);
}

void LoadBase64PrivateKey(const string &filename, PrivateKey &key)
{
	throw runtime_error("Not implemented");
}

void LoadBase64PublicKey(const string &filename, PublicKey &key)
{
	throw runtime_error("Not implemented");
}

void LoadBase64(const string &filename, BufferedTransformation &bt)
{
	throw runtime_error("Not implemented");
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
		rsaPrivate.GenerateRandomWithKeySize(rnd, 2048);

		RSA::PublicKey rsaPublic(rsaPrivate);

		SavePrivateKey("rsa-private.key", rsaPrivate);
		SavePublicKey("rsa-public.key", rsaPublic);

		DSA::PrivateKey dsaPrivate;
		dsaPrivate.GenerateRandomWithKeySize(rnd, 1024);

		DSA::PublicKey dsaPublic;
		dsaPrivate.MakePublicKey(dsaPublic);

		SavePrivateKey("dsa-private.key", dsaPrivate);
		SavePublicKey("dsa-public.key", dsaPublic);

		RSA::PrivateKey r1, r2;
		r1.GenerateRandomWithKeySize(rnd, 3072);

		SavePrivateKey("rsa-roundtrip.key", r1);
		LoadPrivateKey("rsa-roundtrip.key", r2);

		r1.Validate(rnd, 3);
		r2.Validate(rnd, 3);

		if (r1.GetModulus() != r2.GetModulus() ||
			r1.GetPublicExponent() != r2.GetPublicExponent() ||
			r1.GetPrivateExponent() != r2.GetPrivateExponent())
		{
			throw runtime_error("key data did not round trip");
		}

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
