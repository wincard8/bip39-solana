// Solana (SOL) helpers
//
// Solana uses ed25519 keys derived with SLIP-0010 (the same scheme already used
// for Stellar and ZooBC in this tool), so no BIP32/secp256k1 maths is involved.
//
// Wallets (Phantom, Solflare, the Solana CLI, ...) derive accounts from:
//   m/44'/501'/<account>'/0'
//
// A Solana address is the base58 encoding of the 32 byte ed25519 public key.
// The "secret key" that wallets export/import is the base58 encoding of the
// 64 byte value "32 byte seed || 32 byte public key".

function SolanaBase58Encode(bytes) {
    var alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    var digits = [0];
    for (var i = 0; i < bytes.length; i++) {
        var carry = bytes[i];
        for (var j = 0; j < digits.length; j++) {
            carry += digits[j] << 8;
            digits[j] = carry % 58;
            carry = (carry / 58) | 0;
        }
        while (carry > 0) {
            digits.push(carry % 58);
            carry = (carry / 58) | 0;
        }
    }
    var chars = "";
    for (var k = 0; k < bytes.length && bytes[k] === 0; k++) {
        chars += alphabet[0];
    }
    for (var m = digits.length - 1; m >= 0; m--) {
        chars += alphabet[digits[m]];
    }
    return chars;
}

function SolanaGetKeypair(path, seed) {
    var Buffer = libs.buffer.Buffer;
    // SLIP-0010 ed25519 derivation, exposed through the ZooBC helper
    var derived = libs.zoobcUtil.getKeypair(path, seed);
    var privateKey = Buffer.from(derived.key);
    // getPublicKey() returns the 32 byte key prefixed with a SLIP-0010 0x00 byte
    var publicKey = Buffer.from(derived.pubKey.slice(1, 33));
    return {
        path: path,
        privateKey: privateKey,
        publicKey: publicKey,
        address: SolanaBase58Encode(publicKey),
        // 64 byte secret key (seed || public key), as used by Phantom et al.
        secretKey: SolanaBase58Encode(Buffer.concat([privateKey, publicKey])),
    };
}
