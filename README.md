Tornado Cash Encrypted Note.Net: Cypher/Decypher
===========
[![Build status](https://ci.appveyor.com/api/projects/status/buvwa4iu4ifo74a0/branch/master?svg=true)](https://ci.appveyor.com/project/nokitakaze/tornado-cash-encrypted-note-net/branch/master)
[![Test status](https://img.shields.io/appveyor/tests/nokitakaze/tornado-cash-encrypted-note-net)](https://ci.appveyor.com/project/nokitakaze/tornado-cash-encrypted-note-net/branch/master)

This project is a C# implementation of [Tornado Cash](https://docs.tornado.cash/general/how-does-tornado.cash-work)'s encrypted notes.

## Introduction
Tornado Cash notes encrypted with [X25519](https://en.wikipedia.org/wiki/Curve25519)-[XSalsa20](https://en.wikipedia.org/wiki/Salsa20)-[Poly1305](https://en.wikipedia.org/wiki/Poly1305) algorithm.
Each note has structure:
```
- Nonce. 24 bytes: disposable random 24 bytes
- Ephemeral public key. 32 bytes. Public key for a point on Curve25519
- Encrypted message itself including 12 bytes of the Tag of XSalsa20Poly1305
```

Plain text has structure:
`{ContractAddress}-{PrivateCommitment}`
Examples:
- `0x6Bf694a291DF3FeC1f7e69701E3ab6c592435Ae7-0x0e2d09c3b49548799444ae871c1ad7e6dd6110f80e6db8f8e544c33c45234f56caae9b5b4d4d24e1ffbc92b3f94a2228efa28efb363ed96275983a9c64a3`
- `0x84443CFd09A48AF6eF360C6976C5392aC5023a1F-0x8449131cdfbdb26c5834930477fd26425b7d637148414dd0f74fce7feb9b1d9b130e0342dfd9249beaae603e3b07f98a66604029a32d21356c82f224a15f`

**Notice(sic!)** Contract address has "checksummed" format with capital letters.

### Encrypted note events
Event type 0xfa28df43db3553771f7209dcef046f3bdfea15870ab625dcda30ac58b82b4008
- [Ethereum](https://etherscan.io/address/0x722122df12d4e14e13ac3b6895a86e84145b6967#events)
- [Görli](https://goerli.etherscan.io/address/0x454d870a72e29d5e5697f635128d18077bd04c60#events)
- [Binance Smart Chain](https://bscscan.com/address/0x0d5550d52428e7e3175bfc9550207e4ad3859b17#events)

You could find Tornado Cash' contract addresses [here](https://gist.github.com/TheFrozenFire/0dab728cf7884d7c74bb14ede4fcba85).

### Error on the site
At 2022-05-15 official Tornado Cash site has an implementation error: If your note's contract address not in the dictionary, the site will not show you ANY of your private notes.
You could [check it](https://tornadocash.eth.limo/account/) on Goerli network. Private note keys:
- 97a6f440ae04bd21dece386ed83ed65e7bc3405c271e4226f64ed421c197addb
- 97a6f440ae04bd21dece386ed83ed65e7bc3405c271e4226f64ed421c197addd

## Public Interface

* **`Encrypter.CreateRawNoteFrom(string contractAddress, string privateCommitment)`** - Create plain non-crypted note
* **`Encrypter.EncryptNote(string rawNote, string/byte[] notePrivateKey)`** - Encrypt plain note to Encrypted Note format
* **`Decrypter.DecryptNote(string/byte[] encryptedNote, string/byte[] notePrivateKey)`** - Create plain non-crypted note

### Example
Encryption
```C#
var rawNote = Encrypter.CreateRawNoteFrom("0x6bf694a291df3fec1f7e69701e3ab6c592435ae7", "0x0e2d09c3b49548799444ae871c1ad7e6dd6110f80e6db8f8e544c33c45234f56caae9b5b4d4d24e1ffbc92b3f94a2228efa28efb363ed96275983a9c64a3");
var encryptedNote = Encrypter.EncryptNote(rawNote, "97a6f440ae04bd21dece386ed83ed65e7bc3405c271e4226f64ed421c197addb");

var encryptedNoteHex = string.Concat(encryptedNote.Select(t => t.ToFormat("X2")));
Console.WriteLine(encryptedNoteHex);
```

Decryption:
```C#
var encryptedNoteHex = "A27BC84471DD85324572916B32D9E53536C189764010D628DBE5623D805E948F312B192E47D6F0A5C84BF0C7EEB2612916AAF14936C55C579181590D4926B1FFFD37A803303E4147326E61A21BE899D57403B356DF165D84C4228E63627A531ECB4688ABD3BDA925C8FAA1C19369097501C157FBF996BDE8E4A34B1ED51C75BF25B03ED92C1B319118F046EBBA392024DE528922000D98A1BAD0EA08AADC5ED27CF47A595C151C8CC196B23814873F914EB2D466459459BCD18E5827E29BE9699DB7AFF9D5A51BDC8C405845E3611A44058F121F969DA2AC4A101D409D9F74BABA6AE964F5B67E6454E7DBD5791675F02E"
Decrypter.DecryptNote(encryptedNoteHex, "97a6f440ae04bd21dece386ed83ed65e7bc3405c271e4226f64ed421c197addb");
```

## License
Licensed under the Apache License

- X25519-XSalsa20-Poly1305 algorithm: [Daniel J. Bernstein](https://en.wikipedia.org/wiki/Daniel_J._Bernstein)
- [NaCL.Net](https://github.com/somdoron/nacl.net)'s author: [Doron Somech](https://github.com/somdoron)
