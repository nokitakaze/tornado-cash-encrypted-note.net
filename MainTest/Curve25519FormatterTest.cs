using System.Linq;
using System.Security.Cryptography;
using NaCl;
using Xunit;

namespace NokitaKaze.TornadoCashEncryptedNote.MainTest
{
    public class Curve25519FormatterTest
    {
        [Fact]
        public void GetAllCollisionPrivateKeysTest()
        {
            const string sampleText = "raw note";
            using var rng = RandomNumberGenerator.Create();

            for (var i = 0; i < 1000; i++)
            {
                var privateKey = new byte[XSalsa20Poly1305.KeyLength];
                rng.GetBytes(privateKey);
                var privateKeyHex = string.Concat(privateKey.Select(t => t.ToString("x2")));

                var publicKey = new byte[XSalsa20Poly1305.KeyLength];
                Curve25519.ScalarMultiplicationBase(publicKey, privateKey);
                var publicKeyHex = string.Concat(publicKey.Select(t => t.ToString("x2")));

                var encryptedNote = Encrypter.EncryptNote(sampleText, privateKey);

                var collisions = Curve25519Formatter.GetAllCollisionPrivateKeys(privateKey);
                foreach (var collisionKey in collisions)
                {
                    Assert.True(Curve25519Formatter.ArePrivateKeysEqual(privateKey, collisionKey));
                    Assert.False(Curve25519Formatter.ArePrivateKeysSame(privateKey, collisionKey));

                    var collisionKeyHex = string.Concat(collisionKey.Select(t => t.ToString("x2")));
                    Assert.NotEqual(privateKeyHex, collisionKeyHex);

                    var collisionPublicKey = new byte[XSalsa20Poly1305.KeyLength];
                    Curve25519.ScalarMultiplicationBase(collisionPublicKey, collisionKey);
                    var collisionPublicKeyHex = string.Concat(collisionPublicKey.Select(t => t.ToString("x2")));
                    Assert.Equal(publicKeyHex, collisionPublicKeyHex);

                    var message = Decrypter.DecryptNote(encryptedNote, collisionKey);
                    Assert.Equal(sampleText, message);
                }
            }
        }
    }
}