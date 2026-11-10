# BIP39 Tool

A tool for converting BIP39 mnemonic phrases to addresses and private keys.

## This fork: Solana (SOL), Sui (SUI) and Osmosis (OSMO) support, plus a BIP86 (Taproot) tab

This is a fork of [iancoleman/bip39](https://github.com/iancoleman/bip39) that
adds four things:

- a `SOL - Solana` entry in the coin list
- a `SUI - Sui` entry in the coin list
- an `OSMO - Osmosis` entry in the coin list
- a `BIP86` tab that derives Taproot (`bc1p...`) addresses

Everything else about the tool is unchanged.

### Solana (SOL)

Solana uses ed25519 keys derived with SLIP-0010, so it does not go through
BIP32/secp256k1. With `SOL - Solana` selected, every row of the address table is
one Solana account, derived from:

```
m/44'/501'/<account>'/0'
```

| Column | Value for Solana |
| --- | --- |
| Derivation path | `m/44'/501'/<account>'/0'` (all levels hardened) |
| Address | base58 of the 32 byte ed25519 public key |
| Public key | hex of the 32 byte ed25519 public key |
| Private key | base58 of the 64 byte secret key (`seed ‖ public key`), the format Phantom/Solflare/Solana CLI import |

Test vector, BIP39 test mnemonic `abandon abandon ... about` with an empty
passphrase (seed `5eb00bbd...e9e38e4`):

| Account | Address |
| --- | --- |
| 0 | `HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk` |
| 1 | `Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb` |
| 2 | `7WktogJEd2wQ9eH2oWusmcoFTgeYi6rS632UviTBJ2jm` |

The implementation lives in `src/js/solana-util.js` and the `SOL - Solana`
branch in `src/js/index.js`.

### Sui (SUI)

Sui also uses SLIP-0010 ed25519 keys. Every row of the address table is one Sui
account, derived from:

```
m/44'/784'/<account>'/0'/0'
```

A Sui address is the blake2b-256 hash of the one byte signature scheme flag
(`0x00` for ed25519) followed by the 32 byte public key:

```
0x + hex(blake2b-256(0x00 ‖ public_key))
```

| Column | Value for Sui |
| --- | --- |
| Derivation path | `m/44'/784'/<account>'/0'/0'` (all levels hardened) |
| Address | `0x` plus 64 hex characters of the blake2b-256 hash |
| Public key | hex of the 32 byte ed25519 public key |
| Private key | `suiprivkey1...` bech32 export (`flag ‖ secret`), the format the Sui CLI and Sui wallets import |

Test vector, BIP39 test mnemonic `abandon abandon ... about`:

| Account | Address |
| --- | --- |
| 0 | `0x5e93a736d04fbb25737aa40bee40171ef79f65fae833749e3c089fe7cc2161f1` |
| 1 | `0x082d099250999ab8450a9ef3a962edf9e2449e1045be32ba5a0f2c6117ff7167` |
| 2 | `0xf195b51c63745071891b1f53170cac2cab2a49da6ee1fe8eabe50989234c8119` |

The addresses and the `suiprivkey` strings match `@mysten/sui` byte for byte.
The implementation (including a small BLAKE2b-256) lives in
`src/js/sui-util.js`.

### Osmosis (OSMO)

Osmosis is a Cosmos SDK chain, so it uses secp256k1 BIP44 keys with coin type
118 and the `osmo` bech32 prefix. The address is the bech32 encoding of
`ripemd160(sha256(compressed_pubkey))`:

```
m/44'/118'/0'/0/<index>
```

| Column | Value for Osmosis |
| --- | --- |
| Derivation path | `m/44'/118'/0'/0/<index>` (same path as Cosmos Hub) |
| Address | `osmo1...` bech32 of the 20 byte hash160 |
| Public key | hex of the 33 byte compressed secp256k1 public key |
| Private key | hex of the 32 byte secp256k1 private key |

Test vector, BIP39 test mnemonic `abandon abandon ... about`:

| Index | Address |
| --- | --- |
| 0 | `osmo19rl4cm2hmr8afy4kldpxz3fka4jguq0a5m7df8` |
| 1 | `osmo1jrkmdcwgq94uaamx6zax2luewlhf7u4k5r4pqs` |
| 2 | `osmo1kng7tv83qesgvv2ze7hxlw4urfrjk8vqggjsme` |

Addresses match `bip_utils` (`Bip44Coins.OSMOSIS`) exactly. The branch lives in
`src/js/index.js` and reuses `CosmosBufferToAddress` from `cosmos-util.js`.

### Bitcoin Taproot (BIP86)

The `BIP86` tab derives the standard single key Taproot path and encodes the
address as bech32m witness v1:

```
m/86'/0'/0'/0/<index>      receiving
m/86'/0'/0'/1/<index>      change
```

For every derived key the tool computes the BIP341 output key
`Q = P + int(tagged_hash("TapTweak", P.x)) * G` and encodes `Q.x` as `bc1p...`.
The "Public Key" column shows that 32 byte x-only output key, the private key
column shows the WIF of the internal key.

Test vectors, BIP39 test mnemonic `abandon abandon ... about`:

| Path | Address |
| --- | --- |
| `m/86'/0'/0'/0/0` | `bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr` |
| `m/86'/0'/0'/0/1` | `bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh` |
| `m/86'/0'/0'/1/0` | `bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7` |

For any coin without bech32 support the tab reports that BIP86 is unavailable.
The implementation lives in `src/js/taproot-util.js`.

## Online Version

https://iancoleman.io/bip39/

## Standalone offline version

Download `bip39-standalone.html` from
[the releases](https://github.com/iancoleman/bip39/releases).

Open the file in a browser by double clicking it.

This can be compiled from source using the command `python compile.py`

The GitHub Pages build of this fork is `docs/index.html`, produced by running
`python compile.py` and copying `bip39-standalone.html` over it.

## Usage

Enter your BIP39 phrase into the 'BIP39 Phrase' field, or press
'Generate Random Phrase'

If required, set the derivation path, although the defaults are quite usable.

See the table for a list of addresses generated from the phrase.

Toggle columns to blank to easily copy/paste a single column of data, eg to
import private keys into a wallet or supply someone with a list of addresses.

The BIP32 keys can be used at [bip32.org](https://bip32.org) if desired.

## Donations

Since this project is the efforts of many people, most of which don't appear in
the obvious places like code or issues, donating to the project itself causes
significant operational difficulties.

As a result, if you would like to support this project financially you are
encouraged to donate to one of the many groups that makes the internet a place
amenable to projects such as this one.

[Donation-accepting organizations and projects](https://en.bitcoin.it/wiki/Donation-accepting_organizations_and_projects)

If the list is too difficult to choose from, the EFF is a good choice.

[Electronic Frontier Foundation](https://supporters.eff.org/donate)

or for a direct bitcoin address, consider donating to the
[Free Software Foundation](https://www.fsf.org/about/ways-to-donate/)
at 1PC9aZC4hNX2rmmrt7uHTfYAS3hRbph4UN

![alt text](https://static.fsf.org/nosvn/images/bitcoin_qrcodes/fsf.png "FSF Bitcoin Address")

## Making changes

Please do not make modifications to `bip39-standalone.html`, since they will
be overwritten by `compile.py`.

Make changes in `src/*`.

Changes are applied during release using the command `python compile.py`, so
please do not commit changes to `bip39-standalone.html`

# Tests

Tests depend on

* nodejs
* selenium webdriver - cd /path/to/bip39/tests; npm install
* selenium driver for firefox ([geckodriver](https://github.com/mozilla/geckodriver/releases)) and / or chrome ([chromedriver](https://sites.google.com/a/chromium.org/chromedriver/downloads))
* jasmine - npm install --global jasmine

Before running tests, the site must be served at http://localhost:8000.

```
$ cd /path/to/bip39/src
$ python -m http.server

or for python2
$ python -m SimpleHTTPServer
```

Run tests from the command-line

```
$ cd /path/to/bip39/tests
$ jasmine spec/tests.js
```

# License

This BIP39 tool is released under the terms of the MIT license. See LICENSE for
more information or see https://opensource.org/licenses/MIT.
