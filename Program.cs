using System;
using System.IO;
using System.Diagnostics;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Text;
using System.Linq;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Asn1;

using BcX509Extensions = Org.BouncyCastle.Asn1.X509.X509Extensions;
using BcX509Extension = Org.BouncyCastle.Asn1.X509.X509Extension;
using BcPkcsObjectIdentifiers = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers;
using BcAttributePkcs = Org.BouncyCastle.Asn1.Pkcs.AttributePkcs;
using BcAuthorityKeyIdentifier = Org.BouncyCastle.Asn1.X509.AuthorityKeyIdentifier;
using BcGeneralName = Org.BouncyCastle.Asn1.X509.GeneralName;
using BcAccessDescription = Org.BouncyCastle.Asn1.X509.AccessDescription;
using BcAuthorityInformationAccess = Org.BouncyCastle.Asn1.X509.AuthorityInformationAccess;

//using CERTENROLLLib;

namespace certsign
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("-----READING CERTIFICATE REQUEST-----{0}", Environment.NewLine);

            string inFilePath = String.Format(".{0}certs{0}{1}.req", Path.DirectorySeparatorChar, "request");
            Console.WriteLine("Input File: {0}{1}", inFilePath, Environment.NewLine);

            Pkcs10CertificationRequest decodedCsr;
            try
            {
                using (StreamReader reader = File.OpenText(inFilePath))
                {
                    PemReader pemReader = new PemReader(reader);
                    decodedCsr = (Pkcs10CertificationRequest)pemReader.ReadObject();
                }
            }
            catch(PemException e) when (e.Message.Contains("System.ArgumentException"))
            {
                string inFilePathP7b = inFilePath + ".p7b";
                using (StreamWriter sw = new StreamWriter(inFilePathP7b)) 
                {
                    foreach (string line in File.ReadLines(inFilePath))
                    {
                        if (line.StartsWith("-----BEGIN "))
                        {
                            sw.WriteLine("-----BEGIN PKCS7-----");
                        }
                        else if (line.StartsWith("-----END "))
                        {
                            sw.WriteLine("-----END PKCS7-----");
                        }
                        else
                        {
                            sw.WriteLine(line);
                        }
                    }
                }

                try
                {
                    using (StreamReader reader = File.OpenText(inFilePathP7b))
                    using (FileStream fs = File.Create("test.txt"))
                    {
                        PemReader pemReader = new PemReader(reader);
                        var contentInfo = (Org.BouncyCastle.Asn1.Cms.ContentInfo)pemReader.ReadObject();
                        if (BcPkcsObjectIdentifiers.SignedData.Equals(contentInfo.ContentType))
                        {
                            CmsSignedData cmsSignedData = new CmsSignedData(contentInfo);
                            if (BcPkcsObjectIdentifiers.Data.Equals(cmsSignedData.SignedContentType))
                            {
                                cmsSignedData.SignedContent.Write(fs);
                            }
                        }
                    }
                }
                catch(PemException ex)
                {
                    throw ex;
                }

                throw new NotImplementedException("PKCS7 Renewal is not supported. Please create a new CSR and archive the old certificate.");
            }

            var csrSigAlg = decodedCsr.SignatureAlgorithm;
            string sigAlgParams = BitConverter.ToString(csrSigAlg.Parameters.GetEncoded());
            Oid sigAlgOid = Oid.FromOidValue(csrSigAlg.Algorithm.Id, OidGroup.SignatureAlgorithm);

            Console.WriteLine("SignatureAlgorithm: {0} [{1}]", sigAlgOid.FriendlyName, sigAlgParams);
            Console.WriteLine("SignatureValid: {0}{1}", decodedCsr.Verify(), Environment.NewLine);

            var csrInfo = decodedCsr.GetCertificationRequestInfo();

            // Convert BouncyCastle PublicKeyInfo to .NET Core PublicKey class
            var pubKeyInfo = csrInfo.SubjectPublicKeyInfo;
            Oid keyOid = Oid.FromOidValue(pubKeyInfo.AlgorithmID.Algorithm.Id, OidGroup.PublicKeyAlgorithm);
            AsnEncodedData keyParam = new AsnEncodedData(pubKeyInfo.AlgorithmID.Parameters.GetEncoded());
            AsnEncodedData keyValue = new AsnEncodedData(pubKeyInfo.PublicKeyData.GetOctets());
            PublicKey pubKey = new PublicKey(keyOid, keyParam, keyValue);

            //Console.WriteLine(csrInfo.SubjectPublicKeyInfo.AlgorithmID.Algorithm);
            //Console.WriteLine(BitConverter.ToString(csrInfo.SubjectPublicKeyInfo.AlgorithmID.Parameters.GetEncoded()));
            //Console.WriteLine(csrInfo.SubjectPublicKeyInfo.PublicKeyData.PadBits);
            Console.WriteLine("PublicKey: {0} {1}bits", pubKey.Key.KeyExchangeAlgorithm, pubKey.Key.KeySize);
            Console.WriteLine(pubKey.EncodedKeyValue.Format(false));  // certutil.exe -dump
            Console.WriteLine();

            // Convert BouncyCastle X509Name to .NET Core X500DistinguishedName class
            AsnEncodedData subjectAsn = new AsnEncodedData(csrInfo.Subject.GetEncoded());
            X500DistinguishedName subjectDN = new X500DistinguishedName(subjectAsn);

            // Console.WriteLine(csrInfo.Subject);
            Console.WriteLine("DistinguishedName: {0}{1}", subjectDN.Name, Environment.NewLine);

            // Convert BouncyCastle BcAttributePkcs to .NET Core X509Extension class
            List<X509Extension> csrExtensions = new List<X509Extension>();
            foreach (Asn1Encodable ae in csrInfo.Attributes)
            {
                Asn1Object obj = ae.ToAsn1Object();
                BcAttributePkcs attr = BcAttributePkcs.GetInstance(obj);
                if (BcPkcsObjectIdentifiers.Pkcs9AtExtensionRequest.Equals(attr.AttrType))
                {
                    var extensions = BcX509Extensions.GetInstance(attr.AttrValues[0]);
                    foreach (DerObjectIdentifier oid in extensions.ExtensionOids)
                    {
                        BcX509Extension ext = extensions.GetExtension(oid);
                        Oid extOid = Oid.FromOidValue(oid.Id, OidGroup.ExtensionOrAttribute);
                        csrExtensions.Add(BuildX509Extension(extOid, ext.Value.GetOctets(), ext.IsCritical));
                    }
                }
            }

            bool isCa = false;
            bool isOcspSigner = false;

            Console.WriteLine("ExtensionList:");
            foreach (X509Extension extension in csrExtensions)
            {
                Console.WriteLine("{0} ({1})", extension.Oid.FriendlyName, extension.Oid.Value);

                if (extension.Oid.FriendlyName == "Key Usage")
                {
                    X509KeyUsageExtension ext = new X509KeyUsageExtension();
                    ext.CopyFrom(extension);
                    Console.WriteLine(ext.KeyUsages);
                    isCa = ext.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign);
                    isOcspSigner = ext.KeyUsages.HasFlag(X509KeyUsageFlags.CrlSign);
                }
                else if (extension.Oid.FriendlyName == "Enhanced Key Usage")
                {
                    X509EnhancedKeyUsageExtension ext = (X509EnhancedKeyUsageExtension)extension;
                    OidCollection oids = ext.EnhancedKeyUsages;
                    foreach (Oid oid in oids)
                    {
                        Console.WriteLine("EKU: {0} ({1})", oid.FriendlyName, oid.Value);
                    }
                }
            }
            Console.WriteLine();

            Console.WriteLine("-----GENERATING REQUESTED CERTIFICATE-----{0}", Environment.NewLine);

            // Find HashAlgorithm suitable for CSR's SigatureAlgorithm
            // Convert BouncyCastle AlgorithmIdentifier to .NET Core HashAlgorithmName
            var digestAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();
            string digestAlgorithmOidValue = digestAlgFinder.find(csrSigAlg).Algorithm.Id;

            // Convert BouncyCastle AlgorithmIdentifier to .NET Core HashAlgorithmName
            Oid digestAlgorithmOid = Oid.FromOidValue(digestAlgorithmOidValue, OidGroup.HashAlgorithm);
            HashAlgorithmName hashAlgName = new HashAlgorithmName(digestAlgorithmOid.FriendlyName.ToUpperInvariant());

            Console.WriteLine("Found a suitable DigestAlgorithm for this CSR's SignatureAlgorithm");
            Console.WriteLine("HashAlgorithmName: {0}{1}", hashAlgName, Environment.NewLine);

            // Allow 1-Year Validity if End-Entity, or 5-Year Validity if CA
            DateTimeOffset now = DateTimeOffset.UtcNow;
            DateTimeOffset notBefore = now;
            DateTimeOffset notAfter = (isCa || isOcspSigner) ? now.AddMonths(12 * 5) : now.AddDays(365.25);

            Console.WriteLine("Allowing certificate validity till {0}{1}", notAfter, Environment.NewLine);



            //CertificateRequest certRequest = new CertificateRequest(subjectDN, pubKey, hashAlgName);

            X509Certificate2 certificate = null;

            string subjectOfRootIssuer = "OU=Audit";
            if (String.IsNullOrEmpty(subjectOfRootIssuer))
            {
                Console.WriteLine("Generating Private Key for self-signed certificate...");

                var keyName = Guid.NewGuid().ToString();
                var keyParams = new CngKeyCreationParameters();
                keyParams.Provider = new CngProvider("Microsoft Platform Crypto Provider");
                keyParams.UIPolicy = new CngUIPolicy(CngUIProtectionLevels.ProtectKey, null, "Secret Key for " + subjectDN.Name, "PIN for DigitalSigning");
                keyParams.Parameters.Add(
                    new CngProperty("Length", BitConverter.GetBytes(pubKey.Key.KeySize), CngPropertyOptions.Persist));

                // New .NET Core Create(int) method.  Or use
                // rsa = RSA.Create(), rsa.KeySize = newRsaKeySize,
                // or (on .NET Framework) new RSACng(newRsaKeySize)
                //using (RSA rsa = new RSACryptoServiceProvider(pubKey.Key.KeySize, cspParameters))
                using (CngKey rsaKey = CngKey.Create(CngAlgorithm.Rsa, keyName, keyParams))
                using (RSA rsa = new RSACng(rsaKey))
                {
		    if (!rsaKey.IsEphemeral && CngUIProtectionLevels.ProtectKey.Equals(rsaKey.UIPolicy.ProtectionLevel))
                    {
                        CertificateRequest certRequest = new CertificateRequest(subjectDN, rsa, hashAlgName, RSASignaturePadding.Pkcs1);
                        certRequest.ConfigExtensions(csrExtensions, isCa, null, isOcspSigner);
                        certificate = certRequest.IssueCertificate(notBefore, notAfter, null);
                    }
                    else
                    {
                        throw new InvalidOperationException("Error generating Private Key for self-signed certificate");
                    }
                }
            }
            else
            {
                Console.WriteLine("Retrieving suitable Issuer for chain-signed certificate...");

                X509Certificate2 issuerCertificate = GetSuitableIssuer("My", StoreLocation.CurrentUser, subjectOfRootIssuer, subjectDN.Name, notBefore, notAfter);
                if (issuerCertificate == null)
                {
                    throw new InvalidOperationException("No suitable Issuer could not be found. Ensure the X509 Store has a certificate issued by: " + subjectOfRootIssuer);
                }
                else
                {
                    Console.WriteLine("Chosen issuer: {0} ({1}){2}", issuerCertificate.Subject, issuerCertificate.GetNameInfo(X509NameType.EmailName, false), Environment.NewLine);
                }

                // Adjust notAfter if after validity of issuerCertificate
                if (notAfter > issuerCertificate.NotAfter)
                {
                    notAfter = issuerCertificate.NotAfter;
                    Console.WriteLine("Adjusted certificate validity till {0} to match issuer certificate.{1}", notAfter, Environment.NewLine);
                }

                // Get SubjectKeyIdentifier of issuerCertificate
                foreach (X509SubjectKeyIdentifierExtension x509Ski in issuerCertificate.Extensions.OfType<X509SubjectKeyIdentifierExtension>())
                {
                    string issuerSkiHex = x509Ski.SubjectKeyIdentifier;

                    // Add AuthorityKeyIdentifier CertificateExtension
                    var x509Aki = new BcAuthorityKeyIdentifier(issuerSkiHex.DecodeHexString());
                    Oid x509AkiOid = Oid.FromOidValue(BcX509Extensions.AuthorityKeyIdentifier.Id, OidGroup.ExtensionOrAttribute);
                    csrExtensions.Add(BuildX509Extension(x509AkiOid, x509Aki.GetDerEncoded(), false));

                    if (!isOcspSigner)
                    {
                        // Add AuthorityInformationAccess CertificateExtension
                        string ocspRespUri = "https://pki.lmu.co.id/ocsp";
                        string issuerCertUri = String.Format("https://lmu-pki.s3.amazonaws.com/certs/{0}.crt", issuerSkiHex.ToLowerInvariant());
                        BcGeneralName ocspRespLocation = new BcGeneralName(BcGeneralName.UniformResourceIdentifier, ocspRespUri);
                        BcGeneralName issuerCertLocation = new BcGeneralName(BcGeneralName.UniformResourceIdentifier, issuerCertUri);
                        var authorityAccessDesc = new BcAccessDescription[] {
                            new BcAccessDescription(BcAccessDescription.IdADOcsp, ocspRespLocation),
                            new BcAccessDescription(BcAccessDescription.IdADCAIssuers, issuerCertLocation),
                        };
                        //var issuerInfoAccess = new DerSequence(authorityAccessDesc);
                        var issuerInfoAccess = BcAuthorityInformationAccess.GetInstance(new DerSequence(authorityAccessDesc));
                        Oid issuerInfoAccessOid = Oid.FromOidValue(BcX509Extensions.AuthorityInfoAccess.Id, OidGroup.ExtensionOrAttribute);
                        csrExtensions.Add(BuildX509Extension(issuerInfoAccessOid, issuerInfoAccess.GetDerEncoded(), false));
                    }

                    break;
                }



                // pathLen should be 0 for subordinate-CA that will be an issuing-CA
                int? pathLen = null;
                if (isCa) { pathLen = 0; }

                CertificateRequest certRequest = new CertificateRequest(subjectDN, pubKey, hashAlgName);
                certRequest.ConfigExtensions(csrExtensions, isCa, pathLen, isOcspSigner);
                certificate = certRequest.IssueCertificate(notBefore, notAfter, issuerCertificate);
            }
            Console.WriteLine();

            Console.WriteLine("Saving the Certificate belonging to '{0}'...", certificate.GetNameInfo(X509NameType.SimpleName, false));
            string certificateId = certificate.Thumbprint;
            foreach (X509SubjectKeyIdentifierExtension x509Ski in certificate.Extensions.OfType<X509SubjectKeyIdentifierExtension>())
            {
                // SubjectKeyIdentifier is more useful for chain-lookup than certificate.Thumbprint
                certificateId = x509Ski.SubjectKeyIdentifier;
                break;
            }
            string outFilePath = String.Format(".{0}certs{0}{1}.crt", Path.DirectorySeparatorChar, certificateId.ToLowerInvariant());
            File.WriteAllText(outFilePath, certificate.ExportToPem());
            Console.WriteLine("Stored the Certificate under {0}{1}", Path.GetFullPath(outFilePath), Environment.NewLine);

            Console.WriteLine("Finished!");
        }

        static X509Certificate2 GetSuitableIssuer(string storeName, StoreLocation storeLocation, string subjectOfRootIssuer, string subjectName, DateTimeOffset notBefore, DateTimeOffset notAfter)
        {
            X509Certificate2 issuerCertificate = null;

            Regex regexDNOrg = new Regex(@", O=([^,]+),?");
            Match match = regexDNOrg.Match(subjectName);
            string subjectDNOrg = match.Success ? match.Groups[1].Value : null;
            //Console.WriteLine(subjectDNOrg);

            using (X509Store store = new X509Store(storeName, storeLocation))
            {
                store.Open(OpenFlags.OpenExistingOnly);
                Console.WriteLine (@"Store: cert:\{0}\{1}", store.Location, store.Name);

                var caCertificates = store.Certificates
                    .Find(X509FindType.FindByKeyUsage, X509KeyUsageFlags.KeyCertSign, false)
                    .Find(X509FindType.FindByTimeValid, notBefore.LocalDateTime, false);
                    //.Find(X509FindType.FindByTimeValid, notAfter.LocalDateTime, false);

                Console.WriteLine("Choosing between total of {0} CA candidates for Issuer.", caCertificates.Count);

                // Find subordinate CA Certificate with Same Organization
                if (!String.IsNullOrEmpty(subjectDNOrg))
                {
                    var foundCertificates = caCertificates
                        .Find(X509FindType.FindBySubjectName, subjectDNOrg, false);
                    Console.WriteLine("Choosing between {0} subordinate-CA candidates with 'O={1}' for Issuer.", foundCertificates.Count, subjectDNOrg);

                    foreach (X509Certificate2 x509 in foundCertificates)
                    {
                        if (x509.HasPrivateKey &&
                            x509.Subject.Contains("O=" + subjectDNOrg) &&
                            !x509.Issuer.Equals(x509.Subject))
                        {
                            issuerCertificate = x509;
                            break;
                        }
                    }
                }

                // Find First-level subordinate CA Certificate not in Same Organization
                if (issuerCertificate == null)
                {
                    Console.WriteLine("Choosing between any subordinate-CA candidates below '{0}' for Issuer.", subjectOfRootIssuer);

                    foreach (X509Certificate2 x509 in caCertificates)
                    {
                        if (x509.HasPrivateKey &&
                            x509.Issuer.Contains(subjectOfRootIssuer) &&
                            !x509.Issuer.Equals(x509.Subject))
                        {
                            issuerCertificate = x509;
                            break;
                        }
                    }
                }

                // Find Root CA Certificate
                if (issuerCertificate == null)
                {
                    Console.WriteLine("Choosing root-CA with '{0}' for Issuer.", subjectOfRootIssuer);

                    foreach (X509Certificate2 x509 in caCertificates)
                    {
                        if (x509.HasPrivateKey &&
                            x509.Subject.Contains(subjectOfRootIssuer) &&
                            x509.Issuer.Equals(x509.Subject))
                        {
                            issuerCertificate = x509;
                            break;
                        }
                    }
                }
            }

            return issuerCertificate;
        }


        static X509Extension BuildX509Extension(Oid oid, byte[] rawData, bool critical)
        {
            AsnEncodedData data = new AsnEncodedData(oid, rawData);
            switch (oid.FriendlyName)
            {
                case "Key Usage":
                    return new X509KeyUsageExtension(data, critical);
                case "Basic Constraints":
                    return new X509BasicConstraintsExtension(data, critical);
                case "Subject Key Identifier":
                    return new X509SubjectKeyIdentifierExtension(data, critical);
                case "Enhanced Key Usage":
                    return new X509EnhancedKeyUsageExtension(data, critical);
                default:
                    return new X509Extension(data, critical);
            }
        }

    }

    internal static class ExtensionMethods
    {
        // From: https://github.com/dotnet/corefx/blob/master/src/System.Security.Cryptography.X509Certificates/src/Internal/Cryptography/Helpers.cs
        // Decode a hex string-encoded byte array passed to various X509 crypto api.
        // The parsing rules are overly forgiving but for compat reasons, they cannot be tightened.
        public static byte[] DecodeHexString(this string s)
        {
            int whitespaceCount = 0;

            for (int i = 0; i < s.Length; i++)
            {
                if (char.IsWhiteSpace(s[i]))
                    whitespaceCount++;
            }

            uint cbHex = (uint)(s.Length - whitespaceCount) / 2;
            byte[] hex = new byte[cbHex];
            byte accum = 0;
            bool byteInProgress = false;
            int index = 0;

            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];

                if (char.IsWhiteSpace(c))
                {
                    continue;
                }

                accum <<= 4;
                accum |= HexToByte(c);

                byteInProgress = !byteInProgress;

                // If we've flipped from 0 to 1, back to 0, we have a whole byte
                // so add it to the buffer.
                if (!byteInProgress)
                {
                    Debug.Assert(index < cbHex, "index < cbHex");

                    hex[index] = accum;
                    index++;
                }
            }

            // Desktop compat:
            // The desktop algorithm removed all whitespace before the loop, then went up to length/2
            // of what was left.  This means that in the event of odd-length input the last char is
            // ignored, no exception should be raised.
            Debug.Assert(index == cbHex, "index == cbHex");

            return hex;
        }

        private static byte HexToByte(char val)
        {
            if (val <= '9' && val >= '0')
                return (byte)(val - '0');
            else if (val >= 'a' && val <= 'f')
                return (byte)((val - 'a') + 10);
            else if (val >= 'A' && val <= 'F')
                return (byte)((val - 'A') + 10);
            else
                return 0xFF;
        }

        // Certificates content has 64 characters per lines
        private const int MaxCharactersPerLine = 64;

        /// <summary>
        /// Export a certificate to a PEM format string
        /// </summary>
        /// <param name="cert">The certificate to export</param>
        /// <returns>A PEM encoded string</returns>
        public static string ExportToPem(this X509Certificate2 cert)
        {
            var builder = new StringBuilder();
            var certContentBase64 = Convert.ToBase64String(cert.Export(X509ContentType.Cert));
            // Calculates the max number of lines this certificate will take.
            var certMaxNbrLines = Math.Ceiling((double)certContentBase64.Length / MaxCharactersPerLine);

            builder.AppendLine("-----BEGIN CERTIFICATE-----");
            for (var index = 0; index < certMaxNbrLines; index++)
            {
                var maxSubstringLength = index * MaxCharactersPerLine + MaxCharactersPerLine > certContentBase64.Length
                    ? certContentBase64.Length - index * MaxCharactersPerLine
                    : MaxCharactersPerLine;
                builder.AppendLine(certContentBase64.Substring(index * MaxCharactersPerLine, maxSubstringLength));
            }
            builder.AppendLine("-----END CERTIFICATE-----");

            return builder.ToString();
        }

        // KeyUsage & ExtendedKeyUsage:
        // https://www.ibm.com/support/knowledgecenter/en/SSKTMJ_9.0.1/admin/conf_keyusageextensionsandextendedkeyusage_r.html

        public const X509KeyUsageFlags CAFlags =
            X509KeyUsageFlags.CrlSign |
            X509KeyUsageFlags.KeyCertSign;

        public const X509KeyUsageFlags EEFlags =
            X509KeyUsageFlags.KeyAgreement |
            X509KeyUsageFlags.DigitalSignature |
            X509KeyUsageFlags.NonRepudiation;

        public static OidCollection UserEKU = new OidCollection
            {
                Oid.FromOidValue("1.3.6.1.5.5.7.3.2", OidGroup.EnhancedKeyUsage),       // TLS ClientAuth EKU
                Oid.FromOidValue("1.3.6.1.5.5.7.3.4", OidGroup.EnhancedKeyUsage),       // S/MIME Email Protection EKU
                Oid.FromOidValue("1.3.6.1.4.1.311.10.3.12", OidGroup.EnhancedKeyUsage), // Microsoft Document Signing EKU
                new Oid("1.2.840.113583.1.1.5", "Adobe Authentic Documents Trust"),     // Adobe Authentic Documents EKU
            };

        public static OidCollection OcspResponderEKU = new OidCollection
            {
                Oid.FromOidValue("1.3.6.1.5.5.7.3.9", OidGroup.EnhancedKeyUsage),    // OCSP Response Signing EKU
            };

        private static readonly List<string> excludedExtensions = new List<string>
            { "Key Usage", "Enhanced Key Usage", "Application Policies", "Basic Constraints", "Subject Key Identifier" };

        /// <summary>
        /// Configure Certificate Extensions
        /// </summary>
        /// <param name="certExtentions">Additional extensions to add</param>
        /// <returns>The same CertificateRequest for method chaining</returns>
        public static CertificateRequest ConfigExtensions(this CertificateRequest certRequest, List<X509Extension> certExtensions, bool isCa, int? pathLen, bool? isOcspSigner)
        {
            if (certRequest == null) {
                throw new ArgumentException("Null Certificate Request");
            }

            // Config SubjectKeyIdentifier
            certRequest.CertificateExtensions.Add(
                new X509SubjectKeyIdentifierExtension(
                    certRequest.PublicKey,
                    X509SubjectKeyIdentifierHashAlgorithm.Sha1,
                    false));

            // Config subordinate CA or End-Entity?
            certRequest.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(
                    isCa,
                    pathLen.HasValue,
                    pathLen.GetValueOrDefault(),
                    true));

            // Config KeyUsage
            certRequest.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    isCa ? CAFlags : EEFlags,
                    true));

            // Config ExtendedKeyUsage
            if (!isCa)
            {
                certRequest.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension(
                        isOcspSigner.GetValueOrDefault() ? OcspResponderEKU : UserEKU,
                        true));
            }

            // Add SubjectAlternativeNames
            //var sanBuilder = new SubjectAlternativeNameBuilder();
            //sanBuilder.AddEmailAddress("test@frestive.com");
            //sanBuilder.AddDnsName("localhost");
            //sanBuilder.AddIpAddress(System.Net.IPAddress.Parse("127.0.0.1"));
            //sanBuilder.AddIpAddress(System.Net.IPAddress.Parse("[::1]"));
            //certRequest.CertificateExtensions.Add(sanBuilder.Build());

            // Add Other X509 Extensions
            foreach (X509Extension ext in certExtensions)
            {
                if (!excludedExtensions.Contains(ext.Oid.FriendlyName))
                {
                    certRequest.CertificateExtensions.Add(ext);
                }
            }

            return certRequest;
        }

        /// <summary>
        /// Issue Certificate
        /// </summary>
        /// <returns>A new X509Certificate2 that is self-signed or chain-signed</returns>
        public static X509Certificate2 IssueCertificate(this CertificateRequest certRequest, DateTimeOffset notBefore, DateTimeOffset notAfter, X509Certificate2 issuerCertificate)
        {
            if (certRequest == null) {
                throw new ArgumentException("Null Certificate Request");
            }

            if (issuerCertificate == null) {
                Console.WriteLine("Self-Signing Certificate using generated keys...");

                return certRequest.CreateSelfSigned(notBefore, notAfter);

            } else {
                Console.WriteLine("Chain-Signing Certificate using the Issuer's keys...");

                byte[] serialNumber = new byte[8];

                using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(serialNumber);
                }

                AsymmetricAlgorithm key = null;
		try
                {
                    return certRequest.Create(issuerCertificate, notBefore, notAfter, serialNumber);
                }
                catch(InvalidOperationException e) when (e.Message.Contains("X509SignatureGenerator"))
                {
                    X509SignatureGenerator generator;

                    string keyAlgorithmOidValue = issuerCertificate.GetKeyAlgorithm();
                    Oid keyAlgorithmOid = Oid.FromOidValue(keyAlgorithmOidValue, OidGroup.PublicKeyAlgorithm);
                    //Console.WriteLine(keyAlgorithmOid.FriendlyName);
                    switch (keyAlgorithmOid.FriendlyName.ToUpperInvariant())
                    {
                        case "RSA":
                            RSA rsa = issuerCertificate.GetRSAPrivateKey();
                            key = rsa;
                            generator = X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1);
                            break;
                        case "ECC":
                            ECDsa ecdsa = issuerCertificate.GetECDsaPrivateKey();
                            key = ecdsa;
                            generator = X509SignatureGenerator.CreateForECDsa(ecdsa);
                            break;
                        default:
                            generator = null;
                            break;
                    }

                    return certRequest.Create(issuerCertificate.SubjectName, generator, notBefore, notAfter, serialNumber);
                }
                finally
                {
                    key?.Dispose();
                }
            }

        }

    }

}
