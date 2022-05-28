using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using NaCl;
using Nethereum.Util;

namespace NokitaKaze.TornadoCashEncryptedNote
{
    public static class Encrypter
    {
        private static readonly AddressUtil AddressUtil = new AddressUtil();

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static byte[] ParseHex(string hex)
        {
            return Curve25519Formatter.ParseHex(hex);
        }

        public static string CreateRawNoteFrom(string contractAddress, string commitmentSecret)
        {
            contractAddress = AddressUtil.ConvertToChecksumAddress(contractAddress.ToLowerInvariant());
            commitmentSecret = commitmentSecret.ToLowerInvariant();
            if (!commitmentSecret.StartsWith("0x"))
            {
                commitmentSecret = "0x" + commitmentSecret;
            }

            var contractAddressBytes = ParseHex(contractAddress);
            if (contractAddressBytes.Length != 20)
            {
                throw new EncryptedNoteException("Contract address malformed");
            }

            var commitmentSecretBytes = ParseHex(commitmentSecret);
            if (commitmentSecretBytes.Length != 62)
            {
                throw new EncryptedNoteException("Commitment malformed");
            }

            var note = $"{contractAddress}-{commitmentSecret}";
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

            // Create ephemeral key pair
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