using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using NaCl;
using Xunit;

namespace TornadoCashEncryptedNote.MainTest
{
    public class TestDecrypt
    {
        public static IEnumerable<object[]> DecryptNoteTestData()
        {
            var messages = new[]
            {
                // Goerli
                (
                    note:
                    "A27BC84471DD85324572916B32D9E53536C189764010D628DBE5623D805E948F312B192E47D6F0A5C84BF0C7EEB2612916AAF14936C55C579181590D4926B1FFFD37A803303E4147326E61A21BE899D57403B356DF165D84C4228E63627A531ECB4688ABD3BDA925C8FAA1C19369097501C157FBF996BDE8E4A34B1ED51C75BF25B03ED92C1B319118F046EBBA392024DE528922000D98A1BAD0EA08AADC5ED27CF47A595C151C8CC196B23814873F914EB2D466459459BCD18E5827E29BE9699DB7AFF9D5A51BDC8C405845E3611A44058F121F969DA2AC4A101D409D9F74BABA6AE964F5B67E6454E7DBD5791675F02E",
                    expected:
                    "0x6Bf694a291DF3FeC1f7e69701E3ab6c592435Ae7-0x0e2d09c3b49548799444ae871c1ad7e6dd6110f80e6db8f8e544c33c45234f56caae9b5b4d4d24e1ffbc92b3f94a2228efa28efb363ed96275983a9c64a3",
                    privateKey: "97a6f440ae04bd21dece386ed83ed65e7bc3405c271e4226f64ed421c197addb"
                ),
                (
                    note:
                    "EC649C3E934607B1D27C0B8BA6ABB71F4483CC602A3A1B6F9BF4F2BB311E0878AEF3D88A591EDC04132257DBD19F1233FE0475E0290D3C3406146376E4CBE6622DEB4693F8FA6E0896838DDDE4B7A9C4B9D9B7C009056BE9CDC391F166A7DDE7B8D7D91F1AF26708AA74328BBEB535E0EA8521B4D9D2C94867998EAB18F3D13E2FA13E568D33D694A5748D878BA9834CC03E4F3938B18BE4C62CDA09052B155FA2E0A75CFFBE4B02D781C703F9E53EED37AB8F6B388B94FEAD26DBF73AC3C2849524E9ACAC5616D86CB2D5661380C9C31C7C7BBA6D4E7F51F7BC5EEB8F76D9587F2F9A7B2FB140F5C81086262DDC0A9C29",
                    expected:
                    "0x6Bf694a291DF3FeC1f7e69701E3ab6c592435Ae7-0x6db825a364a0073af1167a8b55cbc20ed3b87fb6641ff2d5703cdf0c0bb00a4634108e36c5454334d65e367e98d6e1ba1ed170bc041a1d214e8782f0462d",
                    privateKey: "97a6f440ae04bd21dece386ed83ed65e7bc3405c271e4226f64ed421c197addb"
                ),
                (
                    note:
                    "C8B83EC3A9B899516B9A6DB22264D8D83B9B4F7CF263C0D6048AD3FC7DE5FC95FE646C7454105E11D048974F5515B7B9ADEFFCDEAAD0675C88A1729D8A784A5227240FC4BB2FB62E89F9A64DE4F393D51730E3E03FD660DDEDEB855B0AC41B42DF99BE467BE86D84B7A865641C18CBF92E15FB36C496C4C6C3998379B0CA76F977DC96F97E9F46150508C583C582855F395344F84899ACCFDEF02B36FFE408E419970CB5E47EF8DC477D73BC09DAA1615752837978FD8458F5905A0B82C77861B1127C627E21FE20FC1691DB193219187B2BC217E6B044F114D9BD14B9A8FEFEAA7D99B52A81EBFE267FEB9A84AFFF3E42",
                    expected:
                    "0x6Bf694a291DF3FeC1f7e69701E3ab6c592435Ae7-0x6869179134c52465db560bfb4ed9a15daef7b65f2dfea489befbc40d51db0a1d99b61fe3da39191ba5ae90ecace6cb0c0913eacced093061d045b2556db5",
                    privateKey: "97a6f440ae04bd21dece386ed83ed65e7bc3405c271e4226f64ed421c197addb"
                ),
                (
                    note:
                    "6F7B7F3A79A182333A8F8787B81F96D35A95D0D6337C76DDA328F8FDA59EF63AC8216583C0EAE914C5AF2F24D0DA3D2D9354C4D7EFA564402B3AADF27339BAFD8D7DFCFB6C7132F973F2E2114B055B33134454F0A2D235E84A60A64359FDF4EDD748FCF644A68E0708A392C6B0E965ABDD17A61EA124446E443F04706D5BAFD3DD052C329DB3FE21FBB4711229755009F4D33C6ED3186D16E6A9FDE34EE5489D0C060058406B9F5F9F975D9F7650F08720B48BCBD36DC986B0B395A21D54C9C80632898ABEEC7292BB5B1F94865CA8C46BA983C2879420B127813803A821D48AB34D375A57D2C3DA831C31EA4FCE4A4544",
                    expected:
                    "0x6Bf694a291DF3FeC1f7e69701E3ab6c592435Ae7-0x0d5e4b736dee27bb8e2d235cd33f962379b9b4258ffc80c8c797d668c09560211ca134b103845d783b36a8b529a14b01bdd2e9767345a614274d5b395ea4",
                    privateKey: "97a6f440ae04bd21dece386ed83ed65e7bc3405c271e4226f64ed421c197addb"
                ),

                // Binance Smart Chain
                (
                    note:
                    "4EEF4859CFA322D76913EE1FB74C0A03F4E146D95E02BB6C7B619F0E12C5304EA2B6534509463B674A6EC3255CE0C91410758F23120DA05A72230670624F05D6B4BA573BABD8485DEBB755A3AB089BE5F827BBC513A099892E84B63DC91BF5B48271622619F72BD579D42B81EB35BB38FC737C0E1BD61E2275CEC18FF65976D65F9148B3772CF3E648884DF35C07FAFD3FC90515F88A972504869ADAD18B73D22746A4B89D2AAF4AD1D74DD1253AB06497D47428F231984AD99B86EB75D5163A86EA39E951D04DA31642E99A9F46FD69C9DC74A5758E9F6ECE90703433F87FA1E590FF99470CE8E590AE3C3107394382E3",
                    expected:
                    "0x84443CFd09A48AF6eF360C6976C5392aC5023a1F-0x8449131cdfbdb26c5834930477fd26425b7d637148414dd0f74fce7feb9b1d9b130e0342dfd9249beaae603e3b07f98a66604029a32d21356c82f224a15f",
                    privateKey: "97a6f440ae04bd21dece386ed83ed65e7bc3405c271e4226f64ed421c197addb"
                ),
                (
                    note:
                    "A6D9C8F3A7A8C796A7274C91E4CB0A54DB9D85386012D1FC6F9191E603EC35452EF1554B411A0F9B70C881417646DD2F5D4D42182198F236D8E357DCB1E3DEF345CA54B3A65B674AF83DD9E861EF48005AE69C2F322E847B0447C4B5124943A379502289CBEEA52200FFB98AAD6E97DA2ABF57985D5BC65083F54A10137DF0673B9807A64944323F3AC486A843E045D7CF9E1FEB3C694F0EEB29DD627DE2A3AFE4D87EDE48BA438D2B2B8028F4D54291246FBDBCE2F616B6B31E853A852A1AC7B9C099F1C866B04A3A7E692E54DEE8DC87478ABCF6D9D266AA6512C2C3993E08E8D3166846F1BA2765D56ACE984EAFA46C",
                    expected:
                    "0x84443CFd09A48AF6eF360C6976C5392aC5023a1F-0xeb35c5b82081efd2c65be92ec7daabe18c8c9669105d8ebe938d5f235ba52f5dcc17229ec450df9104ead35b501043727af6afa03a0a4fdc61a0a7b9e23b",
                    privateKey: "97a6f440ae04bd21dece386ed83ed65e7bc3405c271e4226f64ed421c197addb"
                ),
                (
                    note:
                    "79F864341D3B47F68D2B6C67FA8C50687E41015C5EE75ACF8998AD7B8FEDEE6AA44D6C4E58D4363861FB194D73229D4AF1C1F2D94F4CBD7E79660F96C59B5A13A461EC8703B16554B0150D44F9C4E532255433CC160C36AD2BFD4371978A8E48888E0BB8477B0E883A84A30F8B907A0078C4A8FA0E39B5028AD472389ADB05863FADEE7B1461FDB2BB2CD907AC3427ACBE1449CAE76A4F4B3CD2AB93DE37565B761F3C1E326C8386D0B1164F84061FCA97F66AAD01668127E73EDD37549DFFD0E5561EB2997867E4EF3B811579F6E27516129725D6E88D523271C0CD9968A558754F835705BA3D11360F6F1028BAB26AA2",
                    expected:
                    "0x84443CFd09A48AF6eF360C6976C5392aC5023a1F-0x1af55af71f0ae729e8c9601262c3415526ff20921f375c752a5c7d6175aaa2ee20040d6fbe6fb5a9293ca89fd8b0e2afc0a98a4f793443b8f0502de7d3f1",
                    privateKey: "97a6f440ae04bd21dece386ed83ed65e7bc3405c271e4226f64ed421c197addb"
                ),
            };

            return messages.Select(test => new object[] { test.note, test.expected, test.privateKey });
        }

        [Theory]
        [MemberData(nameof(DecryptNoteTestData))]
        public void DecryptNoteTest(
            string encryptedNote,
            string expectedString,
            string privateKey
        )
        {
            if (encryptedNote.StartsWith("0x"))
            {
                encryptedNote = encryptedNote[2..];
            }

            if (privateKey.StartsWith("0x"))
            {
                privateKey = privateKey[2..];
            }

            // ReSharper disable once SuggestVarOrType_BuiltInTypes
            byte[] encryptedNoteBytes = Enumerable
                .Range(0, encryptedNote.Length / 2)
                .Select(offset => byte.Parse(encryptedNote.Substring(offset * 2, 2), NumberStyles.HexNumber))
                .ToArray();

            // ReSharper disable once SuggestVarOrType_BuiltInTypes
            byte[] privateKeyBytes = Enumerable
                .Range(0, privateKey.Length / 2)
                .Select(offset => byte.Parse(privateKey.Substring(offset * 2, 2), NumberStyles.HexNumber))
                .ToArray();

            var actualString = Decrypter.DecryptNote(encryptedNote, privateKey);
            Assert.Equal(expectedString, actualString);

            actualString = Decrypter.DecryptNote(encryptedNoteBytes, privateKey);
            Assert.Equal(expectedString, actualString);

            actualString = Decrypter.DecryptNote(encryptedNote, privateKeyBytes);
            Assert.Equal(expectedString, actualString);

            actualString = Decrypter.DecryptNote(encryptedNoteBytes, privateKeyBytes);
            Assert.Equal(expectedString, actualString);
        }

        [Theory]
        [MemberData(nameof(DecryptNoteTestData))]
        public void DecryptNoteWithBrokenPasswordTest(
            string encryptedNote,
#pragma warning disable xUnit1026
            string _,
#pragma warning restore xUnit1026
            string privateKey
        )
        {
            var rnd = new Random();
            var privateKeyBytes = Encrypter.ParseHex(privateKey);
            for (var i = 0; i < 10; i++)
            {
                var index = rnd.Next(0, privateKeyBytes.Length);
                var privateKeyBytes1 = privateKeyBytes.ToArray();
                while (privateKeyBytes1[index] == privateKeyBytes[index])
                {
                    privateKeyBytes1[index] = (byte)rnd.Next(0, 256);
                }

                try
                {
                    Decrypter.DecryptNote(encryptedNote, privateKeyBytes1);
                    Assert.True(false, "Decrypted didn't raise exception with wrong password");
                }
                catch (EncryptedNoteException)
                {
                }
            }
        }

        [Theory]
        [MemberData(nameof(DecryptNoteTestData))]
        public void DecryptShortNoteTest(
            string encryptedNote,
#pragma warning disable xUnit1026
            string _,
#pragma warning restore xUnit1026
            string privateKey
        )
        {
            const int maxLength =
                2 * (XSalsa20Poly1305.NonceLength + XSalsa20Poly1305.KeyLength + XSalsa20Poly1305.TagLength);
            for (var i = 2; i < maxLength; i += 2)
            {
                var s = encryptedNote[..i];

                try
                {
                    Decrypter.DecryptNote(s, privateKey);
                    Assert.True(false, "Decrypted didn't raise exception with short malformed note");
                }
                catch (EncryptedNoteException)
                {
                }
            }
        }
    }
}