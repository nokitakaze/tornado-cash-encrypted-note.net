using System.Globalization;
using System.Linq;
using System.Numerics;
using Nethereum.Util;
using Xunit;

namespace NokitaKaze.TornadoCashEncryptedNote.MainTest
{
    public class EthereumAddressFormatterTest
    {
        private static readonly AddressUtil AddressUtil = new AddressUtil();

        public static object[][] TestFormat_Data()
        {
            var rawAddresses = new string[]
            {
                "0x4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97",
                "0x7C9b3123f8bB87aEc4d952232C176b86F20B8249",
                "0xe2d892189B69128670311399101785265A6f63E8",
                "0xD3FEEd5DA83D8e8c449d6CB96ff1eb06ED1cF6C7",
                "0xb75B4Dc40A4e3c9d988AA96DA8BAeDCAad5c6654",
                "0x0FE3b6908318B1F630daa5B31B49a15fC5F6B674",
                "0xbDdAE987FEe930910fCC5aa403D5688fB440561B",
                "0xAa843eD65C1f061F111B5289169731351c5e57C1",
                "0x00000000219ab540356cBB839Cbe05303d7705Fa",
                "0x0000000000000000000000000000000000000000",
                "0x0000000000000000000000000000000000000001",
                "0xFfFFff0D254a688b9c1fca74Ff2d137700bA62E1",
            };

            return rawAddresses
                .Select(address => new object[] { address })
                .ToArray();
        }

        [Theory]
        [MemberData(nameof(TestFormat_Data))]
        public void TestFormat(string address)
        {
            Assert.Equal(address, EthereumAddressFormatter.Format(address));
            Assert.Equal(address, EthereumAddressFormatter.Format(address.ToLowerInvariant()));
            Assert.Equal(address, EthereumAddressFormatter.Format(address.ToUpperInvariant()));

            // prefix zero for always positive
            var start = BigInteger.Parse("0" + address[2..], NumberStyles.HexNumber);
            for (var i = 1; i < 10_000; i++)
            {
                var point = start + i;
                var lowered1 = point.ToString("x2", CultureInfo.InvariantCulture)!;
                lowered1 = lowered1.TrimStart('0').PadLeft(40, '0');
                var lowered = "0x" + lowered1;
                var expected = AddressUtil.ConvertToChecksumAddress(lowered);
                var actual = EthereumAddressFormatter.Format(lowered);

                Assert.Equal(expected, actual);

                actual = EthereumAddressFormatter.Format(lowered1);
                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        public void CheckMalformedAddresses()
        {
            var exception = Assert.Throws<EncryptedNoteException>(() =>
                EthereumAddressFormatter.Format("0x4838B1O6FCe9647Bdf1E7877BF73cE8B0BAD5f97"));
            Assert.Equal("Contract address malformed", exception.Message);

            exception = Assert.Throws<EncryptedNoteException>(() =>
                EthereumAddressFormatter.Format("Ox4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97"));
            Assert.Equal("Contract address malformed", exception.Message);

            exception = Assert.Throws<EncryptedNoteException>(() =>
                EthereumAddressFormatter.Format("0x838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97"));
            Assert.Equal("Contract address malformed", exception.Message);

            exception = Assert.Throws<EncryptedNoteException>(() =>
                EthereumAddressFormatter.Format("0x04838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97"));
            Assert.Equal("Contract address malformed", exception.Message);

            exception = Assert.Throws<EncryptedNoteException>(() =>
                EthereumAddressFormatter.Format("0x4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f970"));
            Assert.Equal("Contract address malformed", exception.Message);
        }
    }
}
