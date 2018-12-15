using System;
using System.IO;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace CertificateAPI.Services
{
    public class CertificateService : ICertificateService
    {
        public X509Certificate Generate(
            X509Name issuer,
            AsymmetricKeyParameter issuerPrivate,
            AsymmetricKeyParameter subjectPublic)
        {
            ISignatureFactory signatureFactory;
            if (issuerPrivate is ECPrivateKeyParameters)
            {
                signatureFactory = new Asn1SignatureFactory(
                    X9ObjectIdentifiers.ECDsaWithSha256.ToString(),
                    issuerPrivate);
            }
            else
            {
                signatureFactory = new Asn1SignatureFactory(
                    PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString(),
                    issuerPrivate);
            }

            var certGenerator = new X509V3CertificateGenerator();
            certGenerator.SetIssuerDN(issuer);
            certGenerator.SetSubjectDN(issuer);
            certGenerator.SetSerialNumber(BigInteger.ValueOf(1));
            certGenerator.SetNotAfter(DateTime.UtcNow.AddHours(1));
            certGenerator.SetNotBefore(DateTime.UtcNow);
            certGenerator.SetPublicKey(subjectPublic);
            return certGenerator.Generate(signatureFactory);
        }

        public AsymmetricCipherKeyPair GenerateRsaKeyPair(int length)
        {
            var keygenParam = new KeyGenerationParameters(new SecureRandom(), length);

            var keyGenerator = new RsaKeyPairGenerator();
            keyGenerator.Init(keygenParam);
            return keyGenerator.GenerateKeyPair();
        }

        public (string PublicKey, string PrivateKey) Pkcs1Key(AsymmetricCipherKeyPair keyPair)
        {
            StringWriter privateKey = new StringWriter();
            PemWriter privateKeyPem = new PemWriter(privateKey);
            privateKeyPem.WriteObject(keyPair.Private);
            privateKeyPem.Writer.Close();

            StringWriter publicKey = new StringWriter();
            PemWriter publicKeyPem = new PemWriter(publicKey);
            publicKeyPem.WriteObject(keyPair.Public);
            publicKeyPem.Writer.Close();
            return (PublicKey: publicKey.ToString(), PrivateKey: privateKey.ToString());
        }

        public (string PublicKey, string PrivateKey) Pkcs8Key(AsymmetricCipherKeyPair keyPair)
        {
            StringWriter privateKey = new StringWriter();
            PemWriter privateKeyPem = new PemWriter(privateKey);
            privateKeyPem.WriteObject(new Pkcs8Generator(keyPair.Private));
            privateKeyPem.Writer.Close();

            StringWriter publicKey = new StringWriter();
            PemWriter publicKeyPem = new PemWriter(publicKey);
            publicKeyPem.WriteObject(keyPair.Public);
            publicKeyPem.Writer.Close();
            return (PublicKey: publicKey.ToString(), PrivateKey: privateKey.ToString());
        }
    }
}
