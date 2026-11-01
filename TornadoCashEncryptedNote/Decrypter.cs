using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using NaCl;

namespace NokitaKaze.TornadoCashEncryptedNote
{
    /// <summary>
    /// Decrypts a note sealed with X25519 and XSalsa20-Poly1305.
    /// </summary>
    /// <remarks>
    /// An encrypted note is a 24-byte XSalsa20 nonce, the 32-byte ephemeral X25519 public key,
    /// and the Poly1305-authenticated ciphertext.
    /// The private key is the 32-byte X25519 key the note was encrypted to.
    /// </remarks>
    public static class Decrypter
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static byte[] ParseHex(string hexString)
        {
            return Curve25519Formatter.ParseHex(hexString);
        }

        /// <summary>
        /// Decrypts an encrypted note and returns its UTF-8 plaintext.
        /// </summary>
        /// <param name="encryptedNote">
        /// The encrypted note as hexadecimal text, with or without a <c>0x</c> prefix.
        /// See <see cref="DecryptNoteToBytes"/> for the byte layout.
        /// </param>
        /// <param name="privateKey">
        /// The 32-byte note private key as hexadecimal text, with or without a <c>0x</c> prefix.
        /// </param>
        /// <returns>The decrypted note text.</returns>
        /// <exception cref="FormatException">
        /// <paramref name="encryptedNote"/> or <paramref name="privateKey"/> contains a non-hexadecimal character.
        /// </exception>
        /// <exception cref="EncryptedNoteException">
        /// The private key is not 32 bytes, the note is too short, or authentication fails.
        /// See <see cref="DecryptNoteToBytes"/>.
        /// </exception>
        public static string DecryptNote(string encryptedNote, string privateKey)
        {
            var encryptedNoteBytes = ParseHex(encryptedNote);
            var privateKeyBytes = ParseHex(privateKey);

            return DecryptNote(encryptedNoteBytes, privateKeyBytes);
        }

        /// <summary>
        /// Decrypts an encrypted note and returns its UTF-8 plaintext.
        /// </summary>
        /// <param name="encryptedNote">
        /// The encrypted note as hexadecimal text, with or without a <c>0x</c> prefix.
        /// See <see cref="DecryptNoteToBytes"/> for the byte layout.
        /// </param>
        /// <param name="privateKeyBytes">The 32-byte X25519 private key the note was encrypted to.</param>
        /// <returns>The decrypted note text.</returns>
        /// <exception cref="FormatException">
        /// <paramref name="encryptedNote"/> contains a non-hexadecimal character.
        /// </exception>
        /// <exception cref="EncryptedNoteException">
        /// <paramref name="privateKeyBytes"/> is not 32 bytes, the note is too short, or authentication fails.
        /// See <see cref="DecryptNoteToBytes"/>.
        /// </exception>
        public static string DecryptNote(string encryptedNote, byte[] privateKeyBytes)
        {
            var encryptedNoteBytes = ParseHex(encryptedNote);

            return DecryptNote(encryptedNoteBytes, privateKeyBytes);
        }

        /// <summary>
        /// Decrypts an encrypted note and returns its UTF-8 plaintext.
        /// </summary>
        /// <param name="encryptedNoteBytes">
        /// The encrypted note bytes. See <see cref="DecryptNoteToBytes"/> for the layout.
        /// </param>
        /// <param name="privateKey">
        /// The 32-byte note private key as hexadecimal text, with or without a <c>0x</c> prefix.
        /// </param>
        /// <returns>The decrypted note text.</returns>
        /// <exception cref="FormatException">
        /// <paramref name="privateKey"/> contains a non-hexadecimal character.
        /// </exception>
        /// <exception cref="EncryptedNoteException">
        /// The private key is not 32 bytes, the note is too short, or authentication fails.
        /// See <see cref="DecryptNoteToBytes"/>.
        /// </exception>
        public static string DecryptNote(byte[] encryptedNoteBytes, string privateKey)
        {
            var privateKeyBytes = ParseHex(privateKey);

            return DecryptNote(encryptedNoteBytes, privateKeyBytes);
        }

        /// <summary>
        /// Decrypts an encrypted note and returns its UTF-8 plaintext.
        /// </summary>
        /// <param name="encryptedNoteBytes">
        /// The encrypted note bytes. See <see cref="DecryptNoteToBytes"/> for the layout.
        /// </param>
        /// <param name="privateKeyBytes">The 32-byte X25519 private key the note was encrypted to.</param>
        /// <returns>The decrypted note text.</returns>
        /// <exception cref="EncryptedNoteException">
        /// <paramref name="privateKeyBytes"/> is not 32 bytes, the note is too short, or authentication fails.
        /// See <see cref="DecryptNoteToBytes"/>.
        /// </exception>
        public static string DecryptNote(byte[] encryptedNoteBytes, byte[] privateKeyBytes)
        {
            var bytes = DecryptNoteToBytes(encryptedNoteBytes, privateKeyBytes);
            var decrypted = Encoding.UTF8.GetString(bytes);
            CryptographicOperations.ZeroMemory(bytes);

            return decrypted;
        }

        /// <summary>
        /// Decrypts an encrypted note and returns the plaintext bytes.
        /// </summary>
        /// <param name="encryptedNoteBytes">
        /// The note bytes: a 24-byte XSalsa20 nonce, a 32-byte ephemeral X25519 public key,
        /// and an XSalsa20-Poly1305 ciphertext that includes its 16-byte authentication tag.
        /// </param>
        /// <param name="privateKeyBytes">The 32-byte X25519 private key the note was encrypted to.</param>
        /// <returns>The decrypted plaintext.</returns>
        /// <exception cref="EncryptedNoteException">
        /// <paramref name="privateKeyBytes"/> is not 32 bytes,
        /// <paramref name="encryptedNoteBytes"/> is not longer than the nonce, ephemeral public key, and authentication tag,
        /// or the ciphertext fails authentication.
        /// </exception>
        public static byte[] DecryptNoteToBytes(byte[] encryptedNoteBytes, byte[] privateKeyBytes)
        {
            if (privateKeyBytes.Length != XSalsa20Poly1305.KeyLength)
            {
                throw new EncryptedNoteException("Malformed note private key");
            }

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
            // ReSharper disable once ConvertIfStatementToReturnStatement
            if (!isVerified)
            {
                throw new EncryptedNoteException("Can't decrypt the note");
            }

            return plain;
        }
    }
}
