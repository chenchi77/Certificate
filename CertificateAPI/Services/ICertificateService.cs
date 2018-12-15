using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace CertificateAPI.Services
{
    public interface ICertificateService
    {
        X509Certificate Generate(X509Name issuer, AsymmetricKeyParameter issuerPrivate, AsymmetricKeyParameter subjectPublic);
        AsymmetricCipherKeyPair GenerateRsaKeyPair(int length);
        (string PublicKey, string PrivateKey) Pkcs1Key(AsymmetricCipherKeyPair keyPair);
        (string PublicKey, string PrivateKey) Pkcs8Key(AsymmetricCipherKeyPair keyPair);
    }
}