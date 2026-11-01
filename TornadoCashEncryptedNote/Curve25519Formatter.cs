using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using NaCl;

namespace NokitaKaze.TornadoCashEncryptedNote
{
    /// <summary>
    /// Clamps Curve25519 private keys to the scalar format in
    /// <see href="https://datatracker.ietf.org/doc/html/rfc7748#section-5">RFC 7748, section 5</see>
    /// and compares keys that decode to the same scalar.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A user can, for example, generate 32 uniform random bytes, clear bits 0, 1, 2 of the first byte,
    /// clear bit 7 of the last byte, and set bit 6 of the last byte.
    /// The resulting integer is of the form 2^254 plus eight times a value between 0 and 2^251 - 1 (inclusive).
    /// </para>
    /// <para>
    /// The non-canonical values are 2^255 - 19 through 2^255 - 1 for X25519.
    /// When receiving such an array, implementations of X25519 (but not X448) MUST mask the most significant bit
    /// in the final byte. This is done to preserve compatibility with point formats that reserve the sign bit
    /// for use in other protocols and to increase resistance to implementation fingerprinting.
    /// </para>
    /// <para>
    /// See <see href="https://cr.yp.to/ecdh/curve25519-20060209.pdf">Curve25519: new Diffie-Hellman speed records</see>
    /// and
    /// <see href="https://crypto.stackexchange.com/questions/53318/can-you-help-me-understand-multiplication-of-points-when-using-curve25519">multiplication of points on Curve25519</see>.
    /// </para>
    /// </remarks>
    public static class Curve25519Formatter
    {
        static Curve25519Formatter()
        {
#pragma warning disable CS0162
            // Just in case
            if (XSalsa20Poly1305.KeyLength != Curve25519.ScalarLength)
            {
                throw new Exception("Malformed constants");
            }
#pragma warning restore CS0162
        }

        /// <summary>
        /// Parses a hexadecimal string into bytes.
        /// </summary>
        /// <param name="hex">
        /// Hexadecimal text, with or without a <c>0x</c> prefix. An odd number of digits is padded with a leading zero.
        /// </param>
        /// <returns>The decoded bytes. An empty string decodes to an empty array.</returns>
        /// <exception cref="FormatException"><paramref name="hex"/> contains a non-hexadecimal character.</exception>
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

        #region Format private key to right format

        /// <summary>
        /// Clamps a hexadecimal private key to the Curve25519 scalar format.
        /// </summary>
        /// <param name="hexString">A 32-byte key as hexadecimal text, with or without a <c>0x</c> prefix.</param>
        /// <returns>A new 32-byte array with the RFC 7748 clamp applied.</returns>
        /// <exception cref="FormatException"><paramref name="hexString"/> contains a non-hexadecimal character.</exception>
        /// <exception cref="EncryptedNoteException">The decoded key is not 32 bytes.</exception>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte[] FormatPrivateKey(string hexString)
        {
            return FormatPrivateKey(ParseHex(hexString));
        }

        /// <summary>
        /// Clamps a private key to the Curve25519 scalar format.
        /// </summary>
        /// <param name="bytes">A 32-byte private key. The array is not modified.</param>
        /// <returns>
        /// A copy of <paramref name="bytes"/> with bits 0, 1, and 2 of the first byte cleared,
        /// bit 7 of the last byte cleared, and bit 6 of the last byte set.
        /// </returns>
        /// <exception cref="EncryptedNoteException"><paramref name="bytes"/> is not 32 bytes.</exception>
        // ReSharper disable once ParameterTypeCanBeEnumerable.Global
        public static byte[] FormatPrivateKey(byte[] bytes)
        {
            if (bytes.Length != XSalsa20Poly1305.KeyLength)
            {
                throw new EncryptedNoteException("Malformed note private key");
            }

            var bytesNew = bytes.ToArray();
            bytesNew[0] &= 0b1111_1000; // 0xf8
            bytesNew[31] &= 0b0111_1111; // 0x7f
            bytesNew[31] |= 0b0100_0000; // 0x40

            return bytesNew;
        }

        #endregion

        /// <summary>
        /// Compares two private keys for exact byte equality in constant time.
        /// </summary>
        /// <param name="key1">The first key.</param>
        /// <param name="key2">The second key.</param>
        /// <returns>
        /// <see langword="true"/> when <paramref name="key1"/> and <paramref name="key2"/>
        /// have the same length and the same bytes. The keys are not clamped.
        /// </returns>
        public static bool ArePrivateKeysSame(byte[] key1, byte[] key2)
        {
            return CryptographicOperations.FixedTimeEquals(key1, key2);
        }

        /// <summary>
        /// Compares two private keys after clamping each to the Curve25519 scalar format.
        /// </summary>
        /// <param name="key1">The first 32-byte key.</param>
        /// <param name="key2">The second 32-byte key.</param>
        /// <returns>
        /// <see langword="true"/> when <paramref name="key1"/> and <paramref name="key2"/> clamp to the same bytes.
        /// Keys that differ only in bits 0, 1, and 2 of the first byte, or in bits 6 and 7 of the last byte, compare as equal.
        /// </returns>
        /// <exception cref="EncryptedNoteException">Either key is not 32 bytes.</exception>
        public static bool ArePrivateKeysEqual(byte[] key1, byte[] key2)
        {
            key1 = FormatPrivateKey(key1);
            key2 = FormatPrivateKey(key2);

            return ArePrivateKeysSame(key1, key2);
        }

        /// <summary>
        /// Returns the other 32-byte encodings that clamp to the same Curve25519 scalar as <paramref name="primeKey"/>.
        /// </summary>
        /// <param name="primeKey">A 32-byte private key. The array is not modified.</param>
        /// <returns>
        /// Each other key whose first byte is the clamped first byte plus 0 through 7,
        /// and whose last byte is the clamped last byte with bit 7 either clear or set.
        /// <paramref name="primeKey"/> is omitted when it is one of those keys.
        /// Every returned key yields the same X25519 public key.
        /// </returns>
        /// <exception cref="EncryptedNoteException"><paramref name="primeKey"/> is not 32 bytes.</exception>
        // ReSharper disable once ReturnTypeCanBeEnumerable.Global
        public static byte[][] GetAllCollisionPrivateKeys(byte[] primeKey)
        {
            var formattedKey = FormatPrivateKey(primeKey);

            var allKeys = new List<byte[]>();
            for (byte byte0 = formattedKey[0]; byte0 <= (byte)(formattedKey[0] + 0b111); byte0++)
            {
                var key1 = formattedKey.ToArray();
                key1[0] = byte0;
                allKeys.Add(key1);

                var key2 = key1.ToArray();
                key2[31] |= 0b1000_0000;
                allKeys.Add(key2);

                // ReSharper disable once RedundantCast
                if (byte0 == (byte)0xFF)
                {
                    break;
                }
            }

            return allKeys
                .Where(x => !ArePrivateKeysSame(primeKey, x))
                .ToArray();
        }
    }
}
