// Sui helpers
//
// Sui uses ed25519 keys derived with SLIP-0010 (the the same scheme as Solana,
// Stellar and ZooBC in this tool). Wallets derive accounts from:
//   m/44'/784'/<account>'/0'/0'
//
// A Sui address is the blake2b-256 hash of the one byte signature scheme flag
// (0x00 for ed25519) followed by the 32 byte public key, hex encoded with a 0x
// prefix.
//
// The exported private key uses the "suiprivkey" bech32 format that the Sui CLI
// and Sui wallets import: bech32(hrp="suiprivkey", [flag, 32 byte secret]).

var SUI_BLAKE2B_IV = [
    0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
    0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n
];

var SUI_BLAKE2B_SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]
];

var SUI_MASK64 = 0xFFFFFFFFFFFFFFFFn;

function SuiRotr64(value, bits) {
    var n = BigInt(bits);
    return ((value >> n) | (value << (64n - n))) & SUI_MASK64;
}

function SuiBlake2bCompress(h, block, counter, isLast) {
    var v = new Array(16);
    var i;
    for (i = 0; i < 8; i++) {
        v[i] = h[i];
    }
    for (i = 0; i < 8; i++) {
        v[i + 8] = SUI_BLAKE2B_IV[i];
    }
    v[12] = v[12] ^ (counter & SUI_MASK64);
    v[13] = v[13] ^ ((counter >> 64n) & SUI_MASK64);
    if (isLast) {
        // only f[0] is set for the final block, f[1] stays zero
        v[14] = v[14] ^ SUI_MASK64;
    }

    var m = new Array(16);
    for (i = 0; i < 16; i++) {
        var offset = i * 8;
        // multiplication instead of shifts keeps the value unsigned
        var lo = BigInt(block[offset] + block[offset + 1] * 256 + block[offset + 2] * 65536 + block[offset + 3] * 16777216);
        var hi = BigInt(block[offset + 4] + block[offset + 5] * 256 + block[offset + 6] * 65536 + block[offset + 7] * 16777216);
        m[i] = lo | (hi << 32n);
    }

    function g(a, b, c, d, x, y) {
        v[a] = (v[a] + v[b] + x) & SUI_MASK64;
        v[d] = SuiRotr64(v[d] ^ v[a], 32);
        v[c] = (v[c] + v[d]) & SUI_MASK64;
        v[b] = SuiRotr64(v[b] ^ v[c], 24);
        v[a] = (v[a] + v[b] + y) & SUI_MASK64;
        v[d] = SuiRotr64(v[d] ^ v[a], 16);
        v[c] = (v[c] + v[d]) & SUI_MASK64;
        v[b] = SuiRotr64(v[b] ^ v[c], 63);
    }

    for (var round = 0; round < 12; round++) {
        var s = SUI_BLAKE2B_SIGMA[round % 10];
        g(0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for (i = 0; i < 8; i++) {
        h[i] = h[i] ^ v[i] ^ v[i + 8];
    }
}

// BLAKE2b with a 32 byte digest, unkeyed, as used for Sui addresses
function SuiBlake2b256(input) {
    var h = SUI_BLAKE2B_IV.slice();
    // depth = 1, fanout = 1, key length = 0, digest length = 32
    h[0] = h[0] ^ 0x01010020n;

    var offset = 0;
    var counter = 0n;
    var block;
    while (input.length - offset > 128) {
        block = input.subarray(offset, offset + 128);
        counter += 128n;
        SuiBlake2bCompress(h, block, counter, false);
        offset += 128;
    }
    var remaining = input.length - offset;
    block = new Uint8Array(128);
    block.set(input.subarray(offset, offset + remaining));
    counter += BigInt(remaining);
    SuiBlake2bCompress(h, block, counter, true);

    var out = new Uint8Array(32);
    for (var i = 0; i < 4; i++) {
        var word = h[i];
        for (var j = 0; j < 8; j++) {
            out[i * 8 + j] = Number((word >> BigInt(8 * j)) & 0xffn);
        }
    }
    return libs.buffer.Buffer.from(out);
}

var SUI_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

function SuiBech32Polymod(values) {
    var generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    var chk = 1;
    for (var i = 0; i < values.length; i++) {
        var top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ values[i];
        for (var j = 0; j < 5; j++) {
            if ((top >> j) & 1) {
                chk ^= generator[j];
            }
        }
    }
    return chk >>> 0;
}

function SuiConvertBits(data, fromBits, toBits, pad) {
    var acc = 0;
    var bits = 0;
    var out = [];
    var maxv = (1 << toBits) - 1;
    for (var i = 0; i < data.length; i++) {
        acc = (acc << fromBits) | data[i];
        bits += fromBits;
        while (bits >= toBits) {
            bits -= toBits;
            out.push((acc >> bits) & maxv);
        }
    }
    if (pad && bits > 0) {
        out.push((acc << (toBits - bits)) & maxv);
    }
    return out;
}

function SuiBech32Encode(hrp, words) {
    var expanded = [];
    var i;
    for (i = 0; i < hrp.length; i++) {
        expanded.push(hrp.charCodeAt(i) >> 5);
    }
    expanded.push(0);
    for (i = 0; i < hrp.length; i++) {
        expanded.push(hrp.charCodeAt(i) & 31);
    }
    var values = expanded.concat(words);
    var polymod = SuiBech32Polymod(values.concat([0, 0, 0, 0, 0, 0])) ^ 1;
    var out = hrp + "1";
    for (i = 0; i < words.length; i++) {
        out += SUI_BECH32_CHARSET[words[i]];
    }
    for (i = 0; i < 6; i++) {
        out += SUI_BECH32_CHARSET[(polymod >> (5 * (5 - i))) & 31];
    }
    return out;
}

function SuiEncodePrivateKey(secretKey) {
    // 0x00 is the ed25519 signature scheme flag used by Sui
    var data = [0].concat(Array.prototype.slice.call(secretKey));
    return SuiBech32Encode("suiprivkey", SuiConvertBits(data, 8, 5, true));
}

function SuiGetKeypair(path, seed) {
    var Buffer = libs.buffer.Buffer;
    var derived = libs.zoobcUtil.getKeypair(path, seed);
    var privateKey = Buffer.from(derived.key);
    var publicKey = Buffer.from(derived.pubKey.slice(1, 33));
    var addressBytes = SuiBlake2b256(Buffer.concat([Buffer.from([0]), publicKey]));
    return {
        path: path,
        privateKey: privateKey,
        publicKey: publicKey,
        address: "0x" + addressBytes.toString("hex"),
        secretKey: SuiEncodePrivateKey(privateKey),
    };
}
