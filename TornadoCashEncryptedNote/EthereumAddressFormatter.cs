using System;
using System.Text;
using Epoche;

namespace NokitaKaze.TornadoCashEncryptedNote
{
    /// <summary>
    /// Formats an Ethereum address with the <see href="https://eips.ethereum.org/EIPS/eip-55">EIP-55</see> mixed-case checksum.
    /// </summary>
    public static class EthereumAddressFormatter
    {
        /// <summary>
        /// Returns <paramref name="address"/> as a <c>0x</c>-prefixed hex string whose letter case encodes the EIP-55 checksum.
        /// </summary>
        /// <param name="address">
        /// A 20-byte address as 40 hex characters, with or without a <c>0x</c> prefix. Letter case is ignored.
        /// </param>
        /// <returns>The checksum address, always prefixed with <c>0x</c>.</returns>
        /// <exception cref="EncryptedNoteException">
        /// <paramref name="address"/> is not exactly 40 hexadecimal characters.
        /// </exception>
        public static string Format(string address)
        {
            if (address.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                address = address[2..];
            }

            if (address.Length != 40)
            {
                throw new EncryptedNoteException("Contract address malformed");
            }

            var lower = address.ToLowerInvariant();
            foreach (var c in lower)
            {
                if (c is < '0' or > '9' and < 'a' or > 'f')
                {
                    throw new EncryptedNoteException("Contract address malformed");
                }
            }

            // EIP-55: keccak256 of the lowercase hex string (ASCII), not of the 20 raw bytes.
            var hash = Keccak256.ComputeHash(lower);
            var result = new StringBuilder("0x", 42);
            for (var i = 0; i < lower.Length; i++)
            {
                var c = lower[i];
                var nibble = (hash[i >> 1] >> ((i & 1) == 0 ? 4 : 0)) & 0xF;
                if (c is >= 'a' and <= 'f' && nibble >= 8)
                {
                    c = char.ToUpperInvariant(c);
                }

                result.Append(c);
            }

            return result.ToString();
        }
    }
}
