using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.CompilerServices;
using NaCl;

namespace NokitaKaze.TornadoCashEncryptedNote
{
    /// <summary>
    /// A user can, for example, generate 32 uniform random bytes, clear bits 0, 1, 2 of the first byte,
    /// clear bit 7 of the last byte, and set bit 6 of the last byte.
    /// 
    /// The non-canonical values are 2^255 - 19 through 2^255 - 1 for X25519.
    /// When receiving such an array, implementations of X25519 (but not X448) MUST mask the most significant bit
    /// in the final byte. This is done to preserve compatibility with point formats that reserve the sign bit
    /// for use in other protocols and to increase resistance to implementation fingerprinting.
    ///
    /// This means that the resulting integer is of the form 2^254 plus eight times a value
    /// between 0 and 2^251 - 1 (inclusive).
    /// </summary>
    /// https://datatracker.ietf.org/doc/html/rfc7748#section-5
    /// https://crypto.stackexchange.com/questions/53318/can-you-help-me-understand-multiplication-of-points-when-using-curve25519
    /// https://cr.yp.to/ecdh/curve25519-20060209.pdf
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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte[] FormatPrivateKey(string hexString)
        {
            return FormatPrivateKey(ParseHex(hexString));
        }

        // ReSharper disable once ParameterTypeCanBeEnumerable.Global
        public static byte[] FormatPrivateKey(byte[] bytes)
        {
            var bytesNew = bytes.ToArray();
            bytesNew[0] &= 0b1111_1000; // 0xf8
            bytesNew[31] &= 0b0111_1111; // 0x7f
            bytesNew[31] |= 0b0100_0000; // 0x40

            return bytesNew;
        }

        #endregion

        public static bool ArePrivateKeysSame(byte[] key1, byte[] key2)
        {
            for (var i = 0; i < Curve25519.ScalarLength; i++)
            {
                if (key1[i] != key2[i])
                {
                    return false;
                }
            }

            return true;
        }

        public static bool ArePrivateKeysEqual(byte[] key1, byte[] key2)
        {
            key1 = FormatPrivateKey(key1);
            key2 = FormatPrivateKey(key2);

            return ArePrivateKeysSame(key1, key2);
        }

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