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
using CryptoPP::DL_FixedBasePrecomputation;
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::DL_GroupPrecomputation;
using CryptoPP::ECIES;
using CryptoPP::ECP; // Prime field p
using CryptoPP::ECPPoint;

#include <cryptopp/pubkey.h>
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;

/* standard curves*/
#include <cryptopp/asn.h>
#include <cryptopp/oids.h> //
namespace ASN1 = CryptoPP::ASN1;
using CryptoPP::OID;

int main(int argc, char *argv[])
{
    AutoSeededRandomPool rng;
    // Contruct  ECP(const Integer &modulus, const FieldElement &A, const FieldElement &B);

    // User Defined Domain Parameters for curve y^2 =x^3 + ax +b
    // Modulus p
    Integer p("ffffffff00000001000000000000000000000000ffffffffffffffffffffffffh");
    // Coefiction a
    Integer a("ffffffff00000001000000000000000000000000fffffffffffffffffffffffch");
    // Coefiction b
    Integer b("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bh");
    /* create a curve*/
    a %= p;
    b %= p; // a mod p, b mod p
    /* ECC curve */
    CryptoPP::ECP eqcurve256(p, a, b); // buide curve y^2 =x^3 +ax +b
    /* subgroup <G> on curve */
    // x, y: Base Point G
    Integer x("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296h");
    Integer y("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5h");
    // Creat point G
    ECP::Point G(x, y);
    // Oder n of group <G>
    Integer n("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551h");
    //Cofactors
    Integer h("01h");
    /* Set ECC parameters and subgroup <G>*/
    // CryptoPP::DL_GroupParameters_EC<ECP> curve256(eqcurve256,G,n,h);
    CryptoPP::DL_GroupParameters_EC<ECP> curve256;
    curve256.Initialize(eqcurve256, G, n, h);
    /* Get curve paramaters p, a, b, G, n, h*/

    cout << "prime number p=" << curve256.GetCurve().GetField().GetModulus() << endl;
    cout << "Coefficient  a=" << curve256.GetCurve().GetA() << endl;
    cout << "Coefficient  b=" << curve256.GetCurve().GetB() << endl;

    ECP::Point G1 = curve256.GetSubgroupGenerator();
    cout << "Gx=" << G1.x << endl;
    cout << "Gy=" << G1.y << endl;

    cout << "Subgroup Order n=" << curve256.GetSubgroupOrder() << endl;
    cout << "Cofactor h=" << curve256.GetCofactor() << endl;

    ECP::Point H = curve256.GetCurve().Double(G); // G + G
    cout << "Hx=" << H.x << endl;
    cout << "Hy=" << H.y << endl;

    Integer k("4532.");
    ECP::Point I = curve256.GetCurve().Multiply(k, G); // k * G
    cout << "Ix=" << I.x << endl;
    cout << "Iy=" << I.y << endl;

    ECP::Point J = curve256.GetCurve().Add(H, I); // 2*G + k*G
    cout << "Jx=" << J.x << endl;
    cout << "Jy=" << J.y << endl;

    // Verify
    ECP::Point K = curve256.GetCurve().ScalarMultiply(G, 4534); 
    cout << "Kx=" << K.x << endl;
    cout << "Ky=" << K.y << endl;
    cout << curve256.GetCurve().Equal(J, K)<<endl;
}