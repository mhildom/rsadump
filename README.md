# rsadump

Recover an RSA private key from a Windows process memory dump, using the public key's modulus, and use it to decrypt an RSA-encrypted session key.

I wrote this while working through TryHackMe's *Event Horizon* forensics room, where a C2 implant exchanged an AES session key using RSA. The network capture held the encrypted session key; the private key that could unlock it only existed in the implant's memory. This tool automates finding that key in a dump and recovering the session key.

Full writeup: [Event Horizon: Decrypting a C2 Channel with a Key Pulled from Memory](https://matthildom.dev/posts/event-horizon/)

## How it works

Windows stores RSA private keys in memory as **key blobs** with a fixed binary layout, marked by the magic value `RSA2`. There are two formats, depending on which crypto API created the key:

| | CNG (`BCRYPT_RSAKEY_BLOB`) | CryptoAPI (`PRIVATEKEYBLOB`) |
|---|---|---|
| After `RSA2` + bit length | four length fields (`cbPublicExp`, `cbModulus`, `cbPrime1`, `cbPrime2`) | the public exponent itself |
| Modulus starts at | magic + 24 + `cbPublicExp` | magic + 12 |
| Byte order of values | big-endian | little-endian |

The script:

1. Calculates the key size from the modulus you provide (nothing is hard-coded to 2048 bits).
2. Memory-maps the dump **read-only** and searches for `RSA2` followed by that bit length.
3. Identifies each hit's format from its header. CNG is checked first because its header is the stricter match.
4. Parses `e`, `n`, `p`, and `q` from each blob.
5. Keeps only blobs whose modulus matches yours and where `p * q == n`, then removes duplicate copies of the same key.
6. Calculates the private exponent `d = e⁻¹ mod (p − 1)(q − 1)`, builds the key, and writes it to a PEM file.
7. Decrypts the session key with RSA-OAEP and prints it as Base64.

## Requirements

- Python 3.8+
- PyCryptodome, imported as `Cryptodome`:
  - Debian/Kali: `sudo apt install python3-pycryptodome`
  - pip: `pip install pycryptodomex`

## Usage

```bash
python3 rsadump.py -d <dump file> -m <modulus> -s <encrypted session key>
```

| Argument | Description |
|---|---|
| `-d`, `--dump` | Path to the process memory dump (e.g. a minidump `.dmp`) |
| `-m`, `--modulus` | The known RSA modulus, Base64-encoded (big-endian), either as a string or a path to a file containing it |
| `-s`, `--session-key` | Path to the RSA-encrypted session key as raw bytes |

The modulus is the `<Modulus>` value from a .NET `<RSAKeyValue>` XML public key, which is often what an implant sends during its key exchange.

### Example

```text
$ python3 rsadump.py -d powershell.DMP -m modulus.txt -s session_key_rsa_encrypted.bin
+ Check Length of Modulus
 256
+ cng: 3 blobs, 2 matching the modulus, 2 valid
+ cryptoapi: 0 blobs, 0 matching the modulus, 0 valid
Duplicate cng blob @ offset 39930415
Private Key created
+ Session key (32 bytes): <redacted>
```

The private key is written to `key_<offset>.pem` in the current directory, where `<offset>` is the blob's byte offset in the dump.

## Limitations

- **CryptoAPI support has only been tested against generated test data.** The real dump I built this for only contained CNG keys.
- Only `RSA2` blobs are searched. CNG "full private" blobs (`RSA3`) and public-only blobs aren't handled.
- Decryption uses RSA-OAEP with SHA-1 (the .NET default). Other padding schemes would need a code change.
- The script reads raw file offsets. It doesn't parse the minidump structure, so offsets are positions in the file, not virtual addresses.
- The encrypted session key is currently a required argument.

## Disclaimer

Built for forensic analysis and learning, on evidence you're authorized to examine.
