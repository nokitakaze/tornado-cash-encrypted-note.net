using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using NaCl;
using Xunit;

namespace TornadoCashEncryptedNote.MainTest
{
    public class TestEncrypt
    {
        private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

        public static IEnumerable<object[]> EncryptNoteTestData()
        {
            var addresses = new[]
            {
                "0xD4B88Df4D29F5CedD6857912842cff3b20C8Cfa3",
                "0x84443CFd09A48AF6eF360C6976C5392aC5023a1F",
            };

            var noteKeys = Enumerable
                .Repeat(0, 5)
                .Select(_ =>
                {
                    var key = new byte[XSalsa20Poly1305.KeyLength];
                    Rng.GetBytes(key);

                    return "0x" + string.Concat(key.Select(t => t.ToString("x2")));
                })
                .ToArray();

            var commitmentKeys = Enumerable
                .Repeat(0, 2)
                .Select(_ =>
                {
                    var key = new byte[62];
                    Rng.GetBytes(key);

                    return "0x" + key.Select(t => t.ToString("x2")).Aggregate((a, b) => a + b);
                });

            return addresses
                .SelectMany(address => noteKeys
                    .SelectMany(noteKey => commitmentKeys
                        .Select(commitmentKey => new object[] { address, commitmentKey, noteKey })));
        }

        [Theory]
        [MemberData(nameof(EncryptNoteTestData))]
        public void EncryptNoteTest(
            string contractAddress,
            string commitmentPrivateKey,
            string notePrivateKey
        )
        {
            var a1 = new[]
            {
                contractAddress.ToLowerInvariant(),
                contractAddress,
                contractAddress.ToUpperInvariant(),
            };

            foreach (var localAddress in a1)
            {
                var rawNote = Encrypter.CreateRawNoteFrom(localAddress, commitmentPrivateKey);

                var encryptedNote = Encrypter.EncryptNote(rawNote, notePrivateKey);
                var actualString = Decrypter.DecryptNote(encryptedNote, notePrivateKey);
                Assert.Equal(rawNote, actualString);
            }
        }

        [Fact]
        public void CrawRawNoteTest()
        {
            var addresses = new[]
            {
                "0xD4B88Df4D29F5CedD6857912842cff3b20C8Cfa3",
                "0x84443CFd09A48AF6eF360C6976C5392aC5023a1F",
            };

            for (var i = 0; i < 5; i++)
            {
                var key = new byte[62];
                Rng.GetBytes(key);

                var formedKey = "0x" + key.Select(t => t.ToString("x2")).Aggregate((a, b) => a + b);
                Assert.Equal(62 * 2 + 2, formedKey.Length);
                var subKeys = new[]
                {
                    formedKey,
                    "0x" + formedKey[2..].ToUpperInvariant(),
                    formedKey[2..],
                    formedKey[2..].ToUpperInvariant(),
                };

                foreach (var subKey in subKeys)
                {
                    foreach (var contractAddress in addresses)
                    {
                        var localAddresses = new[]
                        {
                            contractAddress,
                            "0x" + contractAddress[2..].ToLowerInvariant(),
                            "0x" + contractAddress[2..].ToUpperInvariant(),
                            contractAddress[2..],
                            contractAddress[2..].ToLowerInvariant(),
                            contractAddress[2..].ToUpperInvariant(),
                        };
                        var expectedNote = contractAddress + "-" + formedKey;

                        foreach (var localAddress in localAddresses)
                        {
                            var rawNote = Encrypter.CreateRawNoteFrom(localAddress, subKey);
                            Assert.Equal(20 * 2 + 2 + 1 + 62 * 2 + 2, rawNote.Length);

                            Assert.StartsWith(expectedNote, rawNote);
                        }
                    }
                }
            }
        }

        private const string DefaultPlainNote =
            "0x6Bf694a291DF3FeC1f7e69701E3ab6c592435Ae7-0x0e2d09c3b49548799444ae871c1ad7e6dd6110f80e6db8f8e544c33c45234f56caae9b5b4d4d24e1ffbc92b3f94a2228efa28efb363ed96275983a9c64a3";

        [Fact]
        public void EncryptShortKey1Test()
        {
            for (var i = 16; i < XSalsa20Poly1305.KeyLength - 1; i++)
            {
                var bytesShort = new byte[i];
                Rng.GetBytes(bytesShort);

                var fullKey = new byte[XSalsa20Poly1305.KeyLength];
                Array.Copy(bytesShort.Reverse().ToArray(), 0, fullKey, XSalsa20Poly1305.KeyLength - i, i);
                var fullKeyS = "0x" + string.Concat(fullKey.Select(t => t.ToString("x2")));

                var encrypted = Encrypter.EncryptNote(DefaultPlainNote, fullKeyS);
                var decrypted = Decrypter.DecryptNote(encrypted, fullKeyS);
                Assert.Equal(DefaultPlainNote, decrypted);
            }
        }

        [Fact]
        public void EncryptShortKey2Test()
        {
            for (var i = 0; i < XSalsa20Poly1305.KeyLength + 10; i++)
            {
                if (i == XSalsa20Poly1305.KeyLength)
                {
                    continue;
                }

                var bytesShort = new byte[i];
                Rng.GetBytes(bytesShort);

                var shortKeyS = "0x" + string.Concat(bytesShort.Select(t => t.ToString("x2")));

                try
                {
                    Encrypter.EncryptNote(DefaultPlainNote, bytesShort);
                    Assert.True(false, "Encrypted didn't raise exception with short note' private key");
                }
                catch (EncryptedNoteException)
                {
                }

                try
                {
                    Encrypter.EncryptNote(DefaultPlainNote, shortKeyS);
                    Assert.True(false, "Encrypted didn't raise exception with short note' private key");
                }
                catch (EncryptedNoteException)
                {
                }
            }
        }

        [Fact]
        public void CreateMalformedRawNote1Test()
        {
            try
            {
                Encrypter.CreateRawNoteFrom("0x6Bf694a291DF3FeC1f7e69701E3ab6c592435A",
                    "0x0e2d09c3b49548799444ae871c1ad7e6dd6110f80e6db8f8e544c33c45234f56caae9b5b4d4d24e1ffbc92b3f94a2228efa28efb363ed96275983a9c64a3");
                Assert.True(false, "Encrypted didn't raise exception with malformed contract address");
            }
            catch (EncryptedNoteException)
            {
            }
        }

        [Fact]
        public void CreateMalformedRawNote2Test()
        {
            try
            {
                Encrypter.CreateRawNoteFrom("0x6Bf694a291DF3FeC1f7e69701E3ab6c592435Ae7",
                    "0x0e2d09c3b49548799444ae871c1ad7e6dd6110f80e6db8f8e544c33c45234f56caae9b5b4d4d24e1ffbc92b3f94a2228efa28efb363ed96275983a9c64");
                Assert.True(false, "Encrypted didn't raise exception with malformed private commitment");
            }
            catch (EncryptedNoteException)
            {
            }
        }

        [Fact]
        public void UniqueTest()
        {
            const int count = 10_000;
            var values = new List<string>();
            var key = new byte[XSalsa20Poly1305.KeyLength];
            Rng.GetBytes(key);

            for (var i = 0; i < count; i++)
            {
                var encrypted = Encrypter.EncryptNote(DefaultPlainNote, key);
                values.Add(string.Concat(encrypted.Select(t => t.ToString("x2"))));
            }

            Assert.Equal(count, values.Distinct().Count());
        }
    }
}