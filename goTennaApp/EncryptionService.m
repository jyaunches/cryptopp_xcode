//
//  EncryptionService.m
//  goTennaApp
//
//  Created by Julietta Yaunches on 2/6/15.
//  Copyright (c) 2015 Julietta Yaunches. All rights reserved.
//
//  (Vlad Zbarsky also contributed)

#import "EncryptionService.h"

#include <cryptopp/goTennaCrypto.h>

// checking asserts only in debug builds
#if !defined(NDEBUG) && defined(LGTC_DEBUG)
#include <assert.h>
#define		LGTC_ENSURE(x)	assert(x);
#else
#define		LGTC_ENSURE(x)
#endif // !NDEBUG && LGTC_DEBUG

#include <iostream>
using std::ostream;
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;

#include <cryptopp/misc.h>
using CryptoPP::IntToString;

using CryptoPP::ArraySource;

void PrintPrivateKey(const goTennaPrivateKeyType& key, ostream& out = cout);
void PrintPublicKey(const goTennaPublicKeyType& key, ostream& out = cout);

// here you can switch between ECIES procotol and AES-CBC protocol (when implemented)
typedef goTennaCryptoContactECIES cryptoContactType;
//typedef goTennaCryptoContactAESCBC cryptoContactType;

@implementation EncryptionService
-(void)doStuff{
#if !defined(NDEBUG) && defined(LGTC_DEBUG)
    cout << "Debug build, asserts enabled" << endl << endl;
#else
    cout << "Release build, asserts disabled" << endl << endl;
#endif // !NDEBUG && LGTC_DEBUG
    
    AutoSeededRandomPool prng;
    
    //cout << "Using elliptic curve " << ECC_CURVE << endl;
    
    // ECC keypairs for Alice and Bob
    goTennaPrivateKeyType AlicePrivateKey, BobPrivateKey;
    SecByteBlock AlicePrivateKeyExported, BobPrivateKeyExported;
    goTennaPublicKeyType AlicePublicKey, BobPublicKey;
    SecByteBlock AlicePublicKeyExported, BobPublicKeyExported;
    
    // Alice generates her own keypair
    AlicePrivateKey.Initialize(prng, ECC_CURVE);
    AlicePrivateKey.AccessGroupParameters().SetPointCompression(true);
    if (false == AlicePrivateKey.Validate (prng, 2))
        throw runtime_error ("Alice's private key validation failed");
    cout << "Alice generated her private key:" << endl;
    PrintPrivateKey(AlicePrivateKey);
    AlicePrivateKey.MakePublicKey(AlicePublicKey);
    AlicePublicKey.AccessGroupParameters().SetPointCompression(true);
    if (false == AlicePublicKey.Validate (prng, 2))
        throw runtime_error ("Alice's public key validation failed");
    cout << "Alice generated her public key:" << endl;
    PrintPublicKey(AlicePublicKey);
    
    // Alice exports her keypair to byte arrays
    size_t AlicePublicKeyExportedLen = publicKeyToBytes(AlicePublicKey, AlicePublicKeyExported);
    cout << "Alice's public key takes " + IntToString(AlicePublicKeyExportedLen) + " bytes in exported format" << endl;
    size_t AlicePrivateKeyExportedLen = privateKeyToBytes(AlicePrivateKey, AlicePrivateKeyExported);
    cout << "Alice's private key takes " + IntToString(AlicePrivateKeyExportedLen) + " bytes in exported format" << endl;
    
    // Bob generates his own keypair
    BobPrivateKey.Initialize(prng, ECC_CURVE);
    BobPrivateKey.AccessGroupParameters().SetPointCompression(true);
    if (false == BobPrivateKey.Validate (prng, 2))
        throw runtime_error ("Bob's private key validation failed");
    cout << endl << "Bob generated his private key:" << endl;
    PrintPrivateKey(BobPrivateKey);
    BobPrivateKey.MakePublicKey(BobPublicKey);
    BobPublicKey.AccessGroupParameters().SetPointCompression(true);
    if (false == BobPublicKey.Validate (prng, 2))
        throw runtime_error ("Bob's public key validation failed");
    cout << "Bob generated his public key:" << endl;
    PrintPublicKey(BobPublicKey);
    
    // Bob exports his keypair to byte arrays
    size_t BobPublicKeyExportedLen = publicKeyToBytes(BobPublicKey, BobPublicKeyExported);
    cout << "Bob's public key takes " + IntToString(BobPublicKeyExportedLen) + " bytes in exported format" << endl;
    size_t BobPrivateKeyExportedLen = privateKeyToBytes(BobPrivateKey, BobPrivateKeyExported);
    cout << "Bob's private key takes " + IntToString(BobPrivateKeyExportedLen) + " bytes in exported format" << endl;
    
    // Alice sends her public key to Bob
    const byte *AlicePublicKeyBytes = AlicePublicKeyExported.BytePtr();
    
    // Bob receives Alice's public key, and creates a cryptographic object representing his contact with Alice
    cryptoContactType BobsContactForAlice(BobPrivateKey, BobPublicKey, AlicePublicKeyBytes, AlicePublicKeyExportedLen);
    
	// Bob calculates shared secret with Alice
	SecByteBlock sharedSecretBobBytes = BobsContactForAlice.getSharedSecret();
	Integer sharedSecretBobInt;
	sharedSecretBobInt.Decode(sharedSecretBobBytes.BytePtr(), sharedSecretBobBytes.SizeInBytes());
	cout << endl << "Bob calculates shared secret " << std::hex << sharedSecretBobInt << " with Alice" << std::dec << endl;

    // Bob sends his public key to Alice
    const byte *BobPublicKeyBytes = BobPublicKeyExported.BytePtr();
    
    // Alice creates a cryptographic object representing her contact with Bob
    cryptoContactType AlicesContactForBob(AlicePrivateKey, AlicePublicKey, BobPublicKeyBytes, BobPublicKeyExportedLen);
    
	// Alice calculates shared secret with Bob
	SecByteBlock sharedSecretAliceBytes = AlicesContactForBob.getSharedSecret();
	Integer sharedSecretAliceInt;
	sharedSecretAliceInt.Decode(sharedSecretAliceBytes.BytePtr(), sharedSecretAliceBytes.SizeInBytes());
	cout << "Alice calculates shared secret " << std::hex << sharedSecretAliceInt << " with Bob" << std::dec << endl;
	LGTC_ENSURE(sharedSecretAliceInt == sharedSecretBobInt);
	if(sharedSecretAliceInt == sharedSecretBobInt)
		cout << "Alice and Bob successfully calculated identical shared secret " << endl;
	else
    	cerr << "ERROR!!!: Alice and Bob failed to calculate same shared secret" << endl;
   
    // Alice encrypts and sends a text message to Bob
    string cleartextMessageStr = "1234567890", decryptedMessageStr;
    size_t cleartextMessageLen = cleartextMessageStr.size();

// -------- ENCRYPTION BLOCK --------
	// !!! FIXME !!! delete the below, and plug-in actual encryption
	SecByteBlock encryptedMessage((byte *) cleartextMessageStr.c_str(), cleartextMessageStr.size());
	size_t encryptedMessageLen = cleartextMessageLen;
// -------- END OF ENCRYPTION BLOCK --------

    LGTC_ENSURE(encryptedMessageLen == encryptedMessage.SizeInBytes())
    cout << endl << "Alice encrypts message \"" << cleartextMessageStr <<"\" (" << cleartextMessageLen << " bytes before encryption, " << encryptedMessageLen \
    << " bytes after encryption, " << (encryptedMessageLen - cleartextMessageLen) << " overhead) and sends it to Bob" << endl;
    
    // print encrypted message once, to ensure that it was actually encrypted
    string encoded; // encoded (pretty print)
    ArraySource enc_to_hex(encryptedMessage.BytePtr(), encryptedMessageLen, true, new HexEncoder(new StringSink(encoded)));
    cout << "Encrypted message \"" << encoded << "\"" << endl << endl;

    // Bob decrypts and reads Alice's message
// -------- DECRYPTION BLOCK --------
	// !!! FIXME !!! delete the below, and plug-in actual decryption
	SecByteBlock decryptedMessage(encryptedMessage);
	size_t decryptedMessageLen = encryptedMessageLen;
// -------- END OF DECRYPTION BLOCK --------
    if (decryptedMessageLen == 0) { // that would mean decryption failed
        cerr << "ERROR!!!: Bob failed decrypting message from Alice" << endl;
    } else { // decryption succeeded
        decryptedMessageStr = string((char*) decryptedMessage.BytePtr(), decryptedMessageLen);
        cout << "Bob decrypted message from Alice: \"" << decryptedMessageStr << "\" (" << encryptedMessageLen << " bytes before decryption, " \
        << decryptedMessageLen << " bytes after decryption)" << endl;
        if (0 != decryptedMessageStr.compare(cleartextMessageStr))
            cerr << "ERROR!!!: Message decrypted by Bob doesn't match one sent by Alice" << endl;
    }
    LGTC_ENSURE(decryptedMessageLen > 0);
    
    // Bob sends text message to Alice
    cleartextMessageStr = "The quick brown fox jumps over the lazy dog";
    cleartextMessageLen = cleartextMessageStr.size();
// -------- ENCRYPTION BLOCK --------
	// !!! FIXME !!! delete the below, and plug-in actual encryption
	encryptedMessage.Assign((byte *) cleartextMessageStr.c_str(), cleartextMessageStr.size());
	encryptedMessageLen = cleartextMessageLen;
// -------- END OF ENCRYPTION BLOCK --------
    LGTC_ENSURE(encryptedMessageLen == encryptedMessage.SizeInBytes())
    cout << endl << "Bob encrypts message \"" << cleartextMessageStr << "\" (" << cleartextMessageLen << " bytes before encryption, " << encryptedMessageLen \
    << " bytes after encryption, " << (encryptedMessageLen - cleartextMessageLen) << " overhead) and sends it to Alice" << endl;
    
   	// ... on the way it gets corrupted (0th byte gets flipped)
   	cout << endl << "On the way it gets corrupted (0th byte gets flipped)" << endl << endl;
   	encryptedMessage.BytePtr()[0] ^= 0xFF;
    
    // Alice tries to decrypt Bob's message, and sees that it's corrupted
// -------- DECRYPTION BLOCK --------
	// !!! FIXME !!! delete the below, and plug-in actual decryption
	decryptedMessage.Assign(encryptedMessage);
	decryptedMessageLen = encryptedMessageLen;
// -------- END OF DECRYPTION BLOCK --------
/*	LGTC_ENSURE(decryptedMessageLen == 0);
    if (decryptedMessageLen == 0)
        cout << "Alice realizes that Bob's message got corrupted in transit" << endl << endl;
    else
	    cerr << "ERROR!!!: Alice managed to decrypt corrupt message from Bob, something is wrong" << endl << endl;*/
    
    // Alice asks Bob to resend his previous message (via transport protocol, outside of scope of crypto)
    
    // Alice sends Bob another message
    cleartextMessageStr = "Greetings and Salutations";
    cleartextMessageLen = cleartextMessageStr.size();
// -------- ENCRYPTION BLOCK --------
	// !!! FIXME !!! delete the below, and plug-in actual encryption
	encryptedMessage.Assign((byte *) cleartextMessageStr.c_str(), cleartextMessageStr.size());
	encryptedMessageLen = cleartextMessageLen;
// -------- END OF ENCRYPTION BLOCK --------
    LGTC_ENSURE(encryptedMessageLen == encryptedMessage.SizeInBytes())
    cout << "Alice encrypts another message \"" << cleartextMessageStr <<"\" (" << cleartextMessageLen << " bytes before encryption, " << encryptedMessageLen \
    	 << " bytes after encryption, " << (encryptedMessageLen - cleartextMessageLen) << " overhead) and sends it to Bob" << endl << endl;
    
    // Bob decrypts and reads Alice's message
// -------- DECRYPTION BLOCK --------
	// !!! FIXME !!! delete the below, and plug-in actual decryption
	decryptedMessage.Assign(encryptedMessage);
	decryptedMessageLen = encryptedMessageLen;
// -------- END OF DECRYPTION BLOCK --------
    if (decryptedMessageLen == 0) { // that would mean decryption failed
        cerr << "ERROR!!!: Bob failed decrypting message from Alice" << endl;
    } else { // decryption succeeded
        decryptedMessageStr = string((char*) decryptedMessage.BytePtr(), decryptedMessageLen);
        cout << "Bob decrypted another message from Alice: \"" << decryptedMessageStr << "\" (" << encryptedMessageLen << " bytes before decryption, " \
			 << decryptedMessageLen << " bytes after decryption)" << endl << endl;
        if (0 != decryptedMessageStr.compare(cleartextMessageStr))
            cerr << "ERROR!!!: Message decrypted by Bob doesn't match one sent by Alice" << endl << endl;
    }
    LGTC_ENSURE(decryptedMessageLen > 0);
    
    // ----------------------------------------------------------------
    
    goTennaPrivateKeyType BobPrivateKey2;
    goTennaPublicKeyType BobPublicKey2;
    SecByteBlock BobPrivateKey2Exported, BobPublicKey2Exported;
    
    // Bob gets his goTenna radio and smartphone stolen. He buys another smartphone and
    // goTenna radio, generates a new keypair, and sends his new public key to Alice.
    BobPrivateKey2.Initialize(prng, ECC_CURVE);
    BobPrivateKey2.AccessGroupParameters().SetPointCompression(true);
    if (false == BobPrivateKey2.Validate (prng, 2))
        throw runtime_error ("Bob's private key 2 validation failed");
    cout << "Bob has generated private key 2:" << endl;
    PrintPrivateKey(BobPrivateKey2);
    BobPrivateKey2.MakePublicKey(BobPublicKey2);
    BobPublicKey2.AccessGroupParameters().SetPointCompression(true);
    if (false == BobPublicKey2.Validate (prng, 2))
        throw runtime_error ("Bob's public key 2 validation failed");
    cout << endl << "Bob has generated public key 2:" << endl;
    PrintPublicKey(BobPublicKey2);
    
    // Bob receives Alice's public key again
    cryptoContactType BobsContact2ForAlice(BobPrivateKey2, BobPublicKey2, AlicePublicKeyBytes, AlicePublicKeyExportedLen);
    
	// Bob calculates new shared secret with Alice
	SecByteBlock sharedSecretBobBytes2 = BobsContact2ForAlice.getSharedSecret();
	Integer sharedSecretBobInt2;
	sharedSecretBobInt2.Decode(sharedSecretBobBytes2.BytePtr(), sharedSecretBobBytes2.SizeInBytes());
	cout << endl << "Bob calculates new shared secret " << std::hex << sharedSecretBobInt2 << " with Alice" << std::dec << endl;

    // Bob sends his new public key to Alice
    size_t BobPublicKey2ExportedLen = publicKeyToBytes(BobPublicKey2, BobPublicKey2Exported);
    cout << "Bob's public key 2 takes " + IntToString(BobPublicKeyExportedLen) + " bytes in exported format" << endl;
    const byte *BobPublicKey2Bytes = BobPublicKey2Exported.BytePtr();
    
    // Alice updates her contact for Bob with his new public key
    AlicesContactForBob.updateTheirPublicKey(BobPublicKey2Bytes, BobPublicKey2ExportedLen);
    
	// Alice calculates new shared secret with Bob
	SecByteBlock sharedSecretAliceBytes2 = AlicesContactForBob.getSharedSecret();
	sharedSecretAliceInt.Decode(sharedSecretAliceBytes2.BytePtr(), sharedSecretAliceBytes2.SizeInBytes());
	cout << "Alice calculates new shared secret " << std::hex << sharedSecretAliceInt << " with Bob" << std::dec << endl;
	LGTC_ENSURE(sharedSecretAliceInt == sharedSecretBobInt2);
	if(sharedSecretAliceInt == sharedSecretBobInt2)
		cout << "Alice and Bob successfully calculated identical new shared secret " << endl;
	else
    	cerr << "ERROR!!!: Alice and Bob failed to calculate same new shared secret" << endl;

    // Alice sends Bob a message, encrypted to his new key
    cleartextMessageStr = "Bob, I'm sorry you lost your phone";
    cleartextMessageLen = cleartextMessageStr.size();
// -------- ENCRYPTION BLOCK ---------
	// !!! FIXME !!! delete the below, and plug-in actual encryption
	encryptedMessage.Assign((byte *) cleartextMessageStr.c_str(), cleartextMessageStr.size());
	encryptedMessageLen = cleartextMessageLen;
// -------- END OF ENCRYPTION BLOCK --------
    LGTC_ENSURE(encryptedMessageLen == encryptedMessage.SizeInBytes())
    cout << endl << "Alice encrypts message \"" << cleartextMessageStr <<"\" (" << cleartextMessageLen << " bytes before encryption, " << encryptedMessageLen \
    << " bytes after encryption, " << (encryptedMessageLen - cleartextMessageLen) << " overhead) to Bob's new key and sends it to him" << endl;
    
    // Bob decrypts Alice's message with his new key
// -------- DECRYPTION BLOCK --------
	// !!! FIXME !!! delete the below, and plug-in actual decryption
	decryptedMessage.Assign(encryptedMessage);
	decryptedMessageLen = encryptedMessageLen;
// -------- END OF DECRYPTION BLOCK --------
    if (decryptedMessageLen == 0) { // that would mean decryption failed
        cerr << "ERROR!!!: Bob failed decrypting message from Alice" << endl;
    } else { // decryption succeeded
        decryptedMessageStr = string((char*) decryptedMessage.BytePtr(), decryptedMessageLen);
        cout << "Bob decrypted message from Alice with his new key: \"" << decryptedMessageStr << "\" (" << encryptedMessageLen << " bytes before decryption, " \
        << decryptedMessageLen << " bytes after decryption)" << endl;
        if (0 != decryptedMessageStr.compare(cleartextMessageStr))
            cerr << "ERROR!!!: Message decrypted by Bob doesn't match one sent by Alice" << endl;
    }
    LGTC_ENSURE(decryptedMessageLen > 0);
}

void PrintPrivateKey(const goTennaPrivateKeyType& key, ostream& out) {
    const std::ios_base::fmtflags flags = out.flags();
    
    // Group parameters
    const DL_GroupParameters_EC<ECP>& params = key.GetGroupParameters();
    // Base precomputation
    const DL_FixedBasePrecomputation<ECPPoint>& bpc = params.GetBasePrecomputation();
    // Public Key (just do the exponentiation)
    const ECPPoint point = bpc.Exponentiate(params.GetGroupPrecomputation(), key.GetPrivateExponent());
    
    out << "Modulus: " << std::hex << params.GetCurve().GetField().GetModulus() << endl;
    out << "Cofactor: " << std::hex << params.GetCofactor() << endl;
    
    out << "Coefficients" << endl;
    out << "  A: " << std::hex << params.GetCurve().GetA() << endl;
    out << "  B: " << std::hex << params.GetCurve().GetB() << endl;
    
    out << "Base Point" << endl;
    out << "  x: " << std::hex << params.GetSubgroupGenerator().x << endl;
    out << "  y: " << std::hex << params.GetSubgroupGenerator().y << endl;
    
    out << "Public Point" << endl;
    out << "  x: " << std::hex << point.x << endl;
    out << "  y: " << std::hex << point.y << endl;
    
    out << "Private Exponent (multiplicand): " << endl;
    out << "  " << std::hex << key.GetPrivateExponent() << endl;
    
    out << endl;
    out.flags(flags);
}

void PrintPublicKey(const goTennaPublicKeyType& key, ostream& out) {
    const std::ios_base::fmtflags flags = out.flags();
    
    // Group parameters
    const DL_GroupParameters_EC<ECP>& params = key.GetGroupParameters();
    // Public key
    const ECPPoint& point = key.GetPublicElement();
    
    out << "Modulus: " << std::hex << params.GetCurve().GetField().GetModulus() << endl;
    out << "Cofactor: " << std::hex << params.GetCofactor() << endl;
    
    out << "Coefficients" << endl;
    out << "  A: " << std::hex << params.GetCurve().GetA() << endl;
    out << "  B: " << std::hex << params.GetCurve().GetB() << endl;
    
    out << "Base Point" << endl;
    out << "  x: " << std::hex << params.GetSubgroupGenerator().x << endl;
    out << "  y: " << std::hex << params.GetSubgroupGenerator().y << endl;
    
    out << "Public Point" << endl;
    out << "  x: " << std::hex << point.x << endl;
    out << "  y: " << std::hex << point.y << endl;

    out << endl;
    out.flags(flags);
}

@end
