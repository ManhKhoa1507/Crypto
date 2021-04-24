#include <ctime>
#include <iostream>
#include <string>
#include <vector>

#include "./include/cryptopp/aes.h"
#include "./include/cryptopp/filters.h"
#include "./include/cryptopp/hex.h"
#include "./include/cryptopp/cryptlib.h"
#include "./include/cryptopp/osrng.h"
#include "./include/cryptopp/secblock.h"
#include "./include/cryptopp/modes.h"
#include "./include/cryptopp/queue.h"

using CryptoPP::AES;
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;
using CryptoPP::CFB_Mode;
using CryptoPP::HexEncoder;
using CryptoPP::SecByteBlock;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

using namespace std;

void AESHashing()
{
    // Hashing the plaintext using the BlockCipher (AES)

    // vector<char> bytes(plaintext.begin(), plaintext.end());
    // bytes.push_back('\0');

    byte message[] = "Hello there";
    size_t messageLen = strlen((char *)message) + 1;
    cout << message;
    // char *cipher = &bytes[0];
    // size_t cipherLen = strlen((char *)cipher) + 1;

    AutoSeededRandomPool rnd;

    // Create a random key
    SecByteBlock key(0x00, AES::DEFAULT_KEYLENGTH);
    rnd.GenerateBlock(key, key.size());

    // Generate the random iv
    SecByteBlock iv(AES::BLOCKSIZE);
    rnd.GenerateBlock(iv, iv.size());

    // Set the key
    CFB_Mode<AES>::Encryption cfbEncryption(key, key.size(), iv);
    cfbEncryption.ProcessData(message, message, messageLen);

    string encoded = "";
    StringSource ss2(message, true, new HexEncoder(new StringSink(encoded)));
    
    cout << endl
         << message << endl;
    cout << encoded;

    // Encrypt the message
}

double CalHashTime(string input)
{
    // Calculate the hash time of 1 round
    int start_s = clock();

    AESHashing();

    int stop_s = clock();
    double etime = (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000;

    return etime;
}

double CalTotalTime(string plaintext)
{
    // Calculate total time of 10.000 rounds
    double total = 0;
    int round = 0;

    while (round < 10000)
    {
        total = total + CalHashTime(plaintext);
        round++;
    }
    return total;
}

void GetTheInput(string &input)
{
    // Get the input message
    cout << "Please enter input message: ";
    cin >> input;
}

void DisplayResult(string output, double total)
{
    // Display the result (cipherText, total time of 10.000 rounds and Execution time)
    cout << "DES output: " << output << endl;
    cout << "Total time for 10.000 rounds: " << total << " ms" << endl;
    cout << "Execution time: " << total / 10000 << " ms" << endl
         << endl;
}

int main()
{
    //string input;
    //GetTheInput(input);

    AESHashing();
    //double total = CalTotalTime(input);

    //DisplayResult(output, total);
    return 0;
}