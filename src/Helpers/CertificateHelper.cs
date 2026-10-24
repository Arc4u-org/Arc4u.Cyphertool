// Licensed to the Arc4u Foundation under one or more agreements.
// The Arc4u Foundation licenses this file to you under the MIT license.

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Arc4u.Security;
using Arc4u.Security.Cryptography;
using FluentResults;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.Logging;

namespace Arc4u.Cyphertool
{
    internal class CertificateHelper
    {
        public CertificateHelper(ILogger<CertificateHelper> logger, IX509CertificateLoader x509CertificateLoader)
        {
            _logger = logger;
            _x509CertificateLoader = x509CertificateLoader;
        }

        readonly ILogger<CertificateHelper> _logger;
        readonly IX509CertificateLoader _x509CertificateLoader;

        /// <summary>
        /// Load a certificate from a pfx file, from pem files or from the certificate store (keychain).
        /// The source is chosen from the file extension: .pfx or .p12 is a pfx file, .pem, .crt or .cer is a pem certificate,
        /// anything else is the friendly name of a certificate in the store.
        /// </summary>
        /// <param name="privKeyIsExportable">Load the private key of a pfx file as exportable. Needed to extract the key, and to decrypt with an EC certificate on Windows.</param>
        /// <param name="key">The pem private key file of a pem certificate. Without it, only the public key is loaded (enough to encrypt).</param>
        public Result<X509Certificate2> GetCertificate([DisallowNull] string cert, string? password, string? storeName, string? storeLocation, bool privKeyIsExportable = false, string prompt = "Password:", string? key = null)
        {
            ArgumentNullException.ThrowIfNullOrWhiteSpace(cert);

            if (HasExtension(cert, ".pem", ".crt", ".cer"))
            {
                return GetCertificateFromPemFile(cert, key, password, prompt);
            }

            // Certificate is coming from the store if the file name does not end with .pfx or .p12
            bool fromCertStore = !HasExtension(cert, ".pfx", ".p12");

            if (fromCertStore)
            {
                return GetCertificateFromStore(cert, storeName, storeLocation);
            }
            else
            {
                if (string.IsNullOrWhiteSpace(password))
                {
                    password = Prompt.GetPassword(prompt, ConsoleColor.DarkYellow);
                }

                return GetCertificateFromFile(cert, password, privKeyIsExportable);
            }
        }

        private static bool HasExtension(string cert, params string[] extensions)
            => extensions.Any(extension => cert.EndsWith(extension, StringComparison.OrdinalIgnoreCase));

        private Result<X509Certificate2> GetCertificateFromFile(string cert, string? password, bool privKeyIsExportable)
        {
            if (!File.Exists(cert))
            {
                return Result.Fail($"The certificate file {cert} does not exist!");
            }

            return Result.Try(() => System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadPkcs12FromFile(cert, password, privKeyIsExportable ? X509KeyStorageFlags.Exportable : X509KeyStorageFlags.DefaultKeySet));
        }

        /// <summary>
        /// Load a pem (or der) certificate, with its pem private key when <paramref name="key"/> is given.
        /// The private key can be encrypted (ENCRYPTED PRIVATE KEY), its password is then <paramref name="password"/>, prompted when not given.
        /// </summary>
        private Result<X509Certificate2> GetCertificateFromPemFile(string cert, string? key, string? password, string prompt)
        {
            if (!File.Exists(cert))
            {
                return Result.Fail($"The certificate file {cert} does not exist!");
            }

            if (string.IsNullOrWhiteSpace(key))
            {
                return Result.Try(() => System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificateFromFile(cert));
            }

            if (!File.Exists(key))
            {
                return Result.Fail($"The private key file {key} does not exist!");
            }

            if (!File.ReadAllText(key).Contains("-----BEGIN ENCRYPTED PRIVATE KEY-----", StringComparison.Ordinal))
            {
                return Result.Try(() => X509Certificate2.CreateFromPemFile(cert, key));
            }

            if (string.IsNullOrEmpty(password))
            {
                password = Prompt.GetPassword(prompt, ConsoleColor.DarkYellow);
            }

            // .NET gives the same message for a wrong password and for a key not matching the certificate.
            return Result.Try(() => X509Certificate2.CreateFromEncryptedPemFile(cert, password, key),
                              _ => new Error($"The encrypted private key {key} can't be read: the password is wrong or the key doesn't match the certificate {cert}."));
        }
        private Result<X509Certificate2> GetCertificateFromStore(string cert, string? storeName, string? storeLocation)
        {
            var certInfo = new CertificateInfo
            {
                Name = cert
            };

            if (!string.IsNullOrWhiteSpace(storeName))
            {
                try
                {
                    certInfo.StoreName = Enum.Parse<StoreName>(storeName, true);
                }
                catch (Exception)
                {

                    return Result.Fail($"{storeName} is not a valid store!");
                }

            }

            if (!string.IsNullOrWhiteSpace(storeLocation))
            {
                try
                {
                    certInfo.Location = Enum.Parse<StoreLocation>(storeLocation, true);

                }
                catch (Exception)
                {

                    return Result.Fail($"{storeLocation} is not a valid location!");
                }
            }
            _logger.LogInformation("Certificate name is: {Name}", certInfo.Name);
            _logger.LogInformation("Store name is: {StoreName}", certInfo.StoreName);
            _logger.LogInformation("Store location is: {Location}", certInfo.Location);
            _logger.LogInformation("Certificate search is: {FindType}", certInfo.FindType);

            return Result.Try(() => _x509CertificateLoader.FindCertificate(certInfo));
        }

        public Result<string> ConvertPublicKeyToPem(X509Certificate2 x509)
        {
            return Result.Try(() =>
            {
                byte[] certBytes = x509.Export(X509ContentType.Cert);
                return ConvertToPem(certBytes, "CERTIFICATE", true);
            });
        }

        /// <summary>
        /// Export the private key (RSA or EC) in a PKCS#8 pem (PRIVATE KEY), the format read by X509Certificate2.CreateFromPemFile and openssl.
        /// </summary>
        public Result<string> ConvertPrivateKeyToPem(X509Certificate2 x509)
        {
            AsymmetricAlgorithm? privateKey = x509.GetRSAPrivateKey() ?? (AsymmetricAlgorithm?)x509.GetECDsaPrivateKey() ?? x509.GetECDiffieHellmanPrivateKey();
            if (privateKey is null)
            {
                return Result.Fail("The certificate doesn't have a RSA or an EC private key.");
            }
            return Result.Try(() =>
            {
                using (privateKey)
                {
                    return ConvertToPem(privateKey.ExportPkcs8PrivateKey(), "PRIVATE KEY", true);
                }
            });
        }

        /// <summary>
        /// Export the private key (RSA or EC) in an encrypted PKCS#8 pem (ENCRYPTED PRIVATE KEY), protected by AES-256 and <paramref name="password"/>.
        /// Read back by X509Certificate2.CreateFromEncryptedPemFile and openssl.
        /// </summary>
        public Result<string> ConvertEncryptedPrivateKeyToPem(X509Certificate2 x509, string password)
        {
            AsymmetricAlgorithm? privateKey = x509.GetRSAPrivateKey() ?? (AsymmetricAlgorithm?)x509.GetECDsaPrivateKey() ?? x509.GetECDiffieHellmanPrivateKey();
            if (privateKey is null)
            {
                return Result.Fail("The certificate doesn't have a RSA or an EC private key.");
            }
            return Result.Try(() =>
            {
                using (privateKey)
                {
                    var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 600_000);
                    return new string(privateKey.ExportEncryptedPkcs8PrivateKeyPem(password.AsSpan(), pbe)) + Environment.NewLine;
                }
            });
        }

        private string ConvertToPem(string base64EncodedData, bool split = false)
        {
            if (!split)
                return base64EncodedData;

            var sb = new StringBuilder();

            var totalLength = base64EncodedData.Length;
            for (int i = 0; i < base64EncodedData.Length; i += 64)
            {
                var len = Math.Min(64, base64EncodedData.Length - i);
                totalLength -= len;
                if (totalLength > 0)
                    sb.AppendLine(base64EncodedData.Substring(i, len));
                else
                    sb.Append(base64EncodedData.Substring(i, len));
            }

            return sb.ToString();
        }
        private string ConvertToPem(byte[] certBytes, string header, bool split = false)
        {
            var base64EncodedData = Convert.ToBase64String(certBytes);
            var sb = new StringBuilder();
            sb.AppendLine($"-----BEGIN {header}-----");

            sb.AppendLine(ConvertToPem(base64EncodedData, split));

            sb.AppendLine($"-----END {header}-----");
            return sb.ToString();
        }
    }
}
