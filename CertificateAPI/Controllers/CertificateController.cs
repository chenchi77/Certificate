
// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

using System;
using CertificateAPI.Services;
using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Asn1.X509;

namespace CertificateAPI.Controllers
{
    [Route("api/[controller]")]
    public class CertificateController : Controller
    {
        private ICertificateService _certificateService;
        public CertificateController(ICertificateService certificateService)
        {
            _certificateService = certificateService;
        }

        [HttpGet]
        public object Create()
        {
            var caKey = _certificateService.GenerateRsaKeyPair(2048);
            var cert = _certificateService.Generate(new X509Name("CN=Charlie"), caKey.Private, caKey.Public);
            var pkcs1Key = _certificateService.Pkcs1Key(caKey);
            var pkcs8Key = _certificateService.Pkcs8Key(caKey);
            return new
            {
                Cert = Convert.ToBase64String(cert.GetEncoded()),
                Pkcs1Key = pkcs1Key.PrivateKey,
                Pkcs8Key = pkcs8Key.PrivateKey
            };
        }
    }
}
