// Bitcoin Taproot helpers (BIP86 single key addresses)
//
// A Taproot address commits to a tweaked output key:
//   t = tagged_hash("TapTweak", internal_xonly_pubkey) mod n
//   Q = P + t*G           (P is the internal key lifted to an even Y)
// and the address is the bech32m encoding of witness version 1 + Q.x.
//
// secp256k1 point maths is done with BigInt, the hash comes from the
// create-hash library that is already bundled in bip39-libs.js.

var TAPROOT_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
var TAPROOT_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
var TAPROOT_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
var TAPROOT_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

function TaprootMod(a, m) {
    var r = a % m;
    return r < 0n ? r + m : r;
}

function TaprootPow(base, exp, m) {
    var result = 1n;
    base = TaprootMod(base, m);
    while (exp > 0n) {
        if (exp & 1n) {
            result = (result * base) % m;
        }
        base = (base * base) % m;
        exp >>= 1n;
    }
    return result;
}

function TaprootInverse(a, m) {
    return TaprootPow(TaprootMod(a, m), m - 2n, m);
}

function TaprootPointAdd(p1, p2) {
    if (p1 === null) { return p2; }
    if (p2 === null) { return p1; }
    var lambda;
    if (p1.x === p2.x) {
        if (TaprootMod(p1.y + p2.y, TAPROOT_P) === 0n) {
            return null;
        }
        lambda = TaprootMod(3n * p1.x * p1.x * TaprootInverse(2n * p1.y, TAPROOT_P), TAPROOT_P);
    }
    else {
        lambda = TaprootMod((p2.y - p1.y) * TaprootInverse(p2.x - p1.x, TAPROOT_P), TAPROOT_P);
    }
    var x = TaprootMod(lambda * lambda - p1.x - p2.x, TAPROOT_P);
    var y = TaprootMod(lambda * (p1.x - x) - p1.y, TAPROOT_P);
    return { x: x, y: y };
}

function TaprootPointMultiply(point, scalar) {
    var result = null;
    var addend = point;
    var k = scalar;
    while (k > 0n) {
        if (k & 1n) {
            result = TaprootPointAdd(result, addend);
        }
        addend = TaprootPointAdd(addend, addend);
        k >>= 1n;
    }
    return result;
}

function TaprootBytesToBigInt(bytes) {
    var hex = "";
    for (var i = 0; i < bytes.length; i++) {
        hex += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
    }
    return BigInt("0x" + hex);
}

function TaprootBigIntToBytes(value) {
    var hex = value.toString(16);
    while (hex.length < 64) {
        hex = "0" + hex;
    }
    return libs.buffer.Buffer.from(hex, "hex");
}

function TaprootTaggedHash(tag, data) {
    var tagHash = libs.createHash("sha256").update(libs.buffer.Buffer.from(tag, "utf8")).digest();
    return libs.createHash("sha256")
        .update(libs.buffer.Buffer.concat([tagHash, tagHash, data]))
        .digest();
}

// Returns the BIP86 output key for a compressed secp256k1 public key
function TaprootOutputKey(publicKeyBuffer) {
    var Buffer = libs.buffer.Buffer;
    var xOnly = Buffer.from(publicKeyBuffer.slice(1, 33));
    var x = TaprootBytesToBigInt(xOnly);
    // lift_x: the internal key is the x-only key with an even Y coordinate
    var y = TaprootPow(TaprootMod(x * x * x + 7n, TAPROOT_P), (TAPROOT_P + 1n) / 4n, TAPROOT_P);
    if (y % 2n === 1n) {
        y = TAPROOT_P - y;
    }
    var internalPoint = { x: x, y: y };
    var tweak = TaprootMod(
        TaprootBytesToBigInt(TaprootTaggedHash("TapTweak", xOnly)),
        TAPROOT_N
    );
    var tweakPoint = TaprootPointMultiply({ x: TAPROOT_GX, y: TAPROOT_GY }, tweak);
    var outputPoint = TaprootPointAdd(internalPoint, tweakPoint);
    var outputKey = TaprootBigIntToBytes(outputPoint.x);
    return {
        internalKey: xOnly,
        outputKey: outputKey,
        internalKeyHex: xOnly.toString("hex"),
        outputKeyHex: outputKey.toString("hex"),
    };
}

// bech32m (BIP350) encoding used by witness v1 addresses
var TAPROOT_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
var TAPROOT_BECH32_CONST = 0x2bc830a3;

function TaprootBech32Polymod(values) {
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

function TaprootBech32HrpExpand(hrp) {
    var out = [];
    for (var i = 0; i < hrp.length; i++) {
        out.push(hrp.charCodeAt(i) >> 5);
    }
    out.push(0);
    for (var k = 0; k < hrp.length; k++) {
        out.push(hrp.charCodeAt(k) & 31);
    }
    return out;
}

function TaprootConvertBits(data, fromBits, toBits, pad) {
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

function TaprootEncodeAddress(outputKey, hrp) {
    var data = [1].concat(TaprootConvertBits(Array.prototype.slice.call(outputKey), 8, 5, true));
    var values = TaprootBech32HrpExpand(hrp).concat(data);
    var polymod = TaprootBech32Polymod(values.concat([0, 0, 0, 0, 0, 0])) ^ TAPROOT_BECH32_CONST;
    var address = hrp + "1";
    for (var i = 0; i < data.length; i++) {
        address += TAPROOT_BECH32_CHARSET[data[i]];
    }
    for (var j = 0; j < 6; j++) {
        address += TAPROOT_BECH32_CHARSET[(polymod >> (5 * (5 - j))) & 31];
    }
    return address;
}

// Convenience wrapper used by the BIP86 tab
function TaprootAddressFromPublicKey(publicKeyBuffer, hrp) {
    var output = TaprootOutputKey(publicKeyBuffer);
    output.address = TaprootEncodeAddress(output.outputKey, hrp || "bc");
    return output;
}
