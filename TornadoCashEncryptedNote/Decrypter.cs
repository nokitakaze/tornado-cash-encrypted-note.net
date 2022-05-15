using System;
using System.Runtime.CompilerServices;
using System.Text;
using NaCl;

namespace TornadoCashEncryptedNote
{
    public static class Decrypter
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static byte[] ParseHex(string hex)
        {
            return Encrypter.ParseHex(hex);
        }

        public static string DecryptNote(string encryptedNote, string privateKey)
        {
            var encryptedNoteBytes = ParseHex(encryptedNote);
            var privateKeyBytes = ParseHex(privateKey);

            return DecryptNote(encryptedNoteBytes, privateKeyBytes);
        }

        public static string DecryptNote(string encryptedNote, byte[] privateKeyBytes)
        {
            var encryptedNoteBytes = ParseHex(encryptedNote);

            return DecryptNote(encryptedNoteBytes, privateKeyBytes);
        }

        public static string DecryptNote(byte[] encryptedNoteBytes, string privateKey)
        {
            var privateKeyBytes = ParseHex(privateKey);

            return DecryptNote(encryptedNoteBytes, privateKeyBytes);
        }

        public static string DecryptNote(byte[] encryptedNoteBytes, byte[] privateKeyBytes)
        {
            if (encryptedNoteBytes.Length <=
                XSalsa20Poly1305.NonceLength + XSalsa20Poly1305.KeyLength + XSalsa20Poly1305.TagLength)
            {
                throw new EncryptedNoteException("Encrypted note is too short");
            }

            var nonce = new byte[XSalsa20Poly1305.NonceLength];
            Array.Copy(
                encryptedNoteBytes,
                0,
                nonce,
                0,
                XSalsa20Poly1305.NonceLength
            );

            var ephemPublicKey = new byte[XSalsa20Poly1305.KeyLength];
            Array.Copy(
                encryptedNoteBytes,
                XSalsa20Poly1305.NonceLength,
                ephemPublicKey,
                0,
                XSalsa20Poly1305.KeyLength
            );

            var encryptedBytesMessage = new byte[encryptedNoteBytes.Length -
                                                 (XSalsa20Poly1305.KeyLength + XSalsa20Poly1305.NonceLength)];
            Array.Copy(
                encryptedNoteBytes,
                XSalsa20Poly1305.KeyLength + XSalsa20Poly1305.NonceLength,
                encryptedBytesMessage,
                0,
                encryptedBytesMessage.Length
            );

            using var boxPair = new Curve25519XSalsa20Poly1305(privateKeyBytes, ephemPublicKey);

            var plain = new byte[encryptedBytesMessage.Length - XSalsa20Poly1305.TagLength];
            var isVerified = boxPair.TryDecrypt(plain, encryptedBytesMessage, nonce);
            if (!isVerified)
            {
                throw new EncryptedNoteException("Can't verify encrypted note");
            }

            var decrypted = Encoding.UTF8.GetString(plain);
            return decrypted;
        }
    }
}