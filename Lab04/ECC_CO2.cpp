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

int main(int argc, char* argv[])
{
    AutoSeededRandomPool rng;
// Contruct  ECP(const Integer &modulus, const FieldElement &A, const FieldElement &B);

        // User Defined Domain Parameters for curve y^2 =x^3 + ax +b
        OID oid=ASN1::secp384r1(); // standard curves
        CryptoPP::DL_GroupParameters_EC<ECP> curve384;
        curve384.Initialize(oid);
        /* Get curve paramaters p, a, b, G, n, h*/
        Integer p=curve384.GetCurve().GetField().GetModulus();
        cout <<"prime number p="<< p <<endl;
        cout <<"Coefficient  a=" <<curve384.GetCurve().GetA()<<endl;
        cout <<"Coefficient  b=" <<curve384.GetCurve().GetB()<<endl;
        ECP::Point G=curve384.GetSubgroupGenerator();
        cout <<"Gx="<<G.x <<endl;
        cout <<"Gy="<<G.y<<endl;
        cout << "Subgroup Order n=" <<curve384.GetSubgroupOrder()<<endl;
        cout <<"Cofactor h="<< curve384.GetCofactor()<<endl;
        /* Curver Operaton*/
        ECP::Point H=curve384.GetCurve().Double(G); // G+G;
        cout <<"Hx="<<H.x <<endl;
        cout <<"Hy="<<H.y <<endl;
        Integer k("4532.");
        ECP::Point I=curve384.GetCurve().Multiply(k,G); // k.G;
        cout <<"Ix="<<I.x <<endl;
        cout <<"Iy="<<I.y <<endl;
        ECP::Point J=curve384.GetCurve().Add(H,I); // 2G+ k.G;
        cout <<"Jx="<<J.x <<endl;
        cout <<"Jy="<<J.y <<endl;
        //Verify
        ECP::Point K=curve384.GetCurve().ScalarMultiply(G,4534); // 4534.G;
        cout <<"Kx="<<K.x <<endl;
        cout <<"Ky="<<K.y <<endl;
        cout << curve384.GetCurve().Equal(J,K)<<endl;;
        Integer t("27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575.");
        ECP::Point V1(0,ModularSquareRoot(t,p)); 
        ECP::Point V2(0,ModularSquareRoot(t,p)-1);
        cout << curve384.GetCurve().VerifyPoint(V1) << endl;
        cout << curve384.GetCurve().VerifyPoint(V2) << endl;
    }
