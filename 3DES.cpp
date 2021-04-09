#include <ctime>
#include <iostream>
#include <string>

#include "./include/cryptopp/des.h"
#include "./include/cryptopp/filters.h"
#include "./include/cryptopp/hex.h"
#include "./include/cryptopp/cryptlib.h"
#include "./include/cryptopp/osrng.h"
#include "./include/cryptopp/secblock.h"
#include "./include/cryptopp/modes.h"

using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;
using CryptoPP::CBC_Mode;
using CryptoPP::DES;
using CryptoPP::HexEncoder;
using CryptoPP::SecByteBlock;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

using namespace std;

string DESHashing(string plaintext)
{
    // Hashing the plaintext using the BlockCipher (DES)
    string cipher = "";
    string encoded = "";

    CryptoPP::DES des;

    AutoSeededRandomPool prng;

    // Create a random key
    SecByteBlock key(0x00, des.DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    // Generate the block
    byte iv[des.DEFAULT_KEYLENGTH];
    prng.GenerateBlock(iv, sizeof(iv));

    // Set the key
    CBC_Mode<DES>::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);

    // Encrypt the message
    StringSource ss1(plaintext, true, new StreamTransformationFilter(e, new StringSink(cipher)));

    // Print hash output in hex form
    StringSource ss2(cipher, true, new HexEncoder(new StringSink(encoded)));

    return encoded;
}

double HashTime(string input)
{
    // Calculate the hash time of 1 round
    int start_s = clock();

    DESHashing(input);

    int stop_s = clock();
    double etime = (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000;

    return etime;
}

void GetTheInput(string &input)
{
    // Get the input message
    cout << "Please enter input message: ";
    cin >> input;
}

double CalculateTotalTime(string plaintext)
{
    // Calculate total time of 10.000 rounds
    double total = 0;
    int round = 0;

    while (round < 10000)
    {
        total = total + HashTime(plaintext);
        round++;
    }
    return total;
}

void DisplayResult(string cipher, double total)
{
    // Display the result (cipherText, total time of 10.000 rounds and Execution time)
    cout << "DES output: " << cipher << endl;
    cout << "Total time for 10.000 rounds: " << total << " ms" << endl;
    cout << "Execution time: " << total / 10000 << " ms" << endl
         << endl;
}

int main()
{
    string input;
    GetTheInput(input);

    string output = DESHashing(input);
    double total = CalculateTotalTime(input);

    DisplayResult(output, total);
    return 0;
}
