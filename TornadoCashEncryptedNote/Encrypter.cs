using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using NaCl;

namespace NokitaKaze.TornadoCashEncryptedNote
{
    /// <summary>
    /// Builds a deposit note and seals it with X25519 and XSalsa20-Poly1305.
    /// </summary>
    /// <remarks>
    /// An encrypted note is a 24-byte XSalsa20 nonce, the 32-byte ephemeral X25519 public key,
    /// and the Poly1305-authenticated ciphertext.
    /// The private key is the 32-byte X25519 key the note is encrypted to.
    /// </remarks>
    public static class Encrypter
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static byte[] ParseHex(string hex)
        {
            return Curve25519Formatter.ParseHex(hex);
        }

        /// <summary>
        /// Builds the plaintext deposit note from a contract address and a commitment secret.
        /// </summary>
        /// <param name="contractAddress">
        /// A 20-byte contract address as 40 hex characters, with or without a <c>0x</c> prefix.
        /// Letter case is ignored. The address is written with the checksum from
        /// <see cref="EthereumAddressFormatter.Format(string)"/>.
        /// </param>
        /// <param name="commitmentSecret">
        /// A 62-byte secret as hexadecimal text, with or without a <c>0x</c> prefix. Letter case is ignored.
        /// </param>
        /// <returns>
        /// The checksum address, a hyphen, and <paramref name="commitmentSecret"/> as lowercase hex with a <c>0x</c> prefix.
        /// </returns>
        /// <exception cref="EncryptedNoteException">
        /// <paramref name="contractAddress"/> is not 40 hexadecimal characters,
        /// or <paramref name="commitmentSecret"/> is not 62 bytes.
        /// </exception>
        /// <exception cref="System.FormatException">
        /// <paramref name="commitmentSecret"/> contains a non-hexadecimal character.
        /// </exception>
        public static string CreateRawNoteFrom(string contractAddress, string commitmentSecret)
        {
            contractAddress = EthereumAddressFormatter.Format(contractAddress);
            commitmentSecret = commitmentSecret.ToLowerInvariant();
            if (!commitmentSecret.StartsWith("0x"))
            {
                commitmentSecret = "0x" + commitmentSecret;
            }

            var commitmentSecretBytes = ParseHex(commitmentSecret);
            if (commitmentSecretBytes.Length != 62)
            {
                throw new EncryptedNoteException("Commitment malformed");
            }

            var note = $"{contractAddress}-{commitmentSecret}";
            return note;
        }

        /// <summary>
        /// Encrypts a note for an X25519 private key.
        /// </summary>
        /// <param name="rawNote">
        /// The plaintext note, encoded as UTF-8. This is typically the value returned by <see cref="CreateRawNoteFrom"/>.
        /// </param>
        /// <param name="privateKey">
        /// The 32-byte note private key as hexadecimal text, with or without a <c>0x</c> prefix.
        /// </param>
        /// <returns>
        /// The encrypted note. See <see cref="EncryptNote(string, byte[])"/> for the byte layout.
        /// </returns>
        /// <exception cref="System.FormatException">
        /// <paramref name="privateKey"/> contains a non-hexadecimal character.
        /// </exception>
        /// <exception cref="EncryptedNoteException">
        /// <paramref name="privateKey"/> is not 32 bytes, or the ciphertext does not decrypt with that key.
        /// </exception>
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

        /// <summary>
        /// Encrypts a note for an X25519 private key.
        /// </summary>
        /// <param name="rawNote">
        /// The plaintext note, encoded as UTF-8. This is typically the value returned by <see cref="CreateRawNoteFrom"/>.
        /// </param>
        /// <param name="privateKey">The 32-byte X25519 private key the note is encrypted to.</param>
        /// <returns>
        /// A new encrypted note. Each call uses a fresh nonce and ephemeral key, so the same inputs produce different bytes.
        /// The layout is a 24-byte XSalsa20 nonce, the 32-byte ephemeral X25519 public key,
        /// and the XSalsa20-Poly1305 ciphertext, which <see cref="Decrypter.DecryptNoteToBytes"/> accepts.
        /// </returns>
        /// <exception cref="EncryptedNoteException">
        /// <paramref name="privateKey"/> is not 32 bytes, or the ciphertext does not decrypt with that key.
        /// </exception>
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
            CryptographicOperations.ZeroMemory(ephemSecretKey);

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
