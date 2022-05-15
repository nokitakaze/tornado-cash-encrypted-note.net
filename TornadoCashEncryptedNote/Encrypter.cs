using System;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using NaCl;
using Nethereum.Util;

namespace TornadoCashEncryptedNote
{
    public static class Encrypter
    {
        private static readonly AddressUtil AddressUtil = new AddressUtil();

        public static byte[] ParseHex(string hex)
        {
            var s = hex;
            if (s.StartsWith("0x"))
            {
                s = s[2..];
            }

            var n = (int)(2 * Math.Ceiling(s.Length * 0.5));
            s = s.PadLeft(n, '0');
            return Enumerable
                .Range(0, n / 2)
                .Select(t => byte.Parse(s.Substring(t * 2, 2), NumberStyles.HexNumber))
                .ToArray();
        }

        public static string CreateRawNoteFrom(string contractAddress, string privateCommitment)
        {
            contractAddress = AddressUtil.ConvertToChecksumAddress(contractAddress.ToLowerInvariant());
            privateCommitment = privateCommitment.ToLowerInvariant();
            if (!privateCommitment.StartsWith("0x"))
            {
                privateCommitment = "0x" + privateCommitment;
            }

            var contractAddressBytes = ParseHex(contractAddress);
            if (contractAddressBytes.Length != 20)
            {
                throw new EncryptedNoteException("Contract address malformed");
            }

            var privateCommitmentBytes = ParseHex(privateCommitment);
            if (privateCommitmentBytes.Length != 62)
            {
                throw new EncryptedNoteException("Commitment malformed");
            }

            var note = $"{contractAddress}-{privateCommitment}";
            return note;
        }

        public static byte[] EncryptNote(string rawNote, string privateKey)
        {
            var bytes = ParseHex(privateKey);
            // ReSharper disable once InvertIf
            if (bytes.Length != XSalsa20Poly1305.KeyLength)
            {
                throw new EncryptedNoteException("Malformed note private key");
            }

            return EncryptNote(rawNote, bytes);
        }

        public static byte[] EncryptNote(string rawNote, byte[] privateKey)
        {
            if (privateKey.Length != XSalsa20Poly1305.KeyLength)
            {
                throw new EncryptedNoteException("Malformed note private key");
            }

            var encryptedNotePublicKey = new byte[XSalsa20Poly1305.KeyLength];
            Curve25519.ScalarMultiplicationBase(encryptedNotePublicKey, privateKey);

            // Create ephemerical key pair
            Curve25519XSalsa20Poly1305.KeyPair(out var ephemSecretKey, out var ephemPublicKey);

            using var ephemBoxPair = new Curve25519XSalsa20Poly1305(ephemSecretKey, encryptedNotePublicKey);

            using var rng = RandomNumberGenerator.Create();
            var nonce = new byte[XSalsa20Poly1305.NonceLength];
            rng.GetBytes(nonce);

            var fullNoteBytes = Encoding.UTF8.GetBytes(rawNote);
            var cipher = new byte[fullNoteBytes.Length + XSalsa20Poly1305.TagLength];
            ephemBoxPair.Encrypt(cipher, fullNoteBytes, nonce);

            // Verify encrypted note
            using var userBoxPair = new Curve25519XSalsa20Poly1305(privateKey, ephemPublicKey);
            var testBack = new byte[fullNoteBytes.Length];
            var isVerified = userBoxPair.TryDecrypt(testBack, cipher, nonce);
            if (!isVerified)
            {
                throw new EncryptedNoteException("Can't verify ciphered note");
            }

            var encryptedNote = nonce.Concat(ephemPublicKey).Concat(cipher).ToArray();
            return encryptedNote;
        }
    }
}