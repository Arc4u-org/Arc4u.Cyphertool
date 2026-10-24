// Licensed to the Arc4u Foundation under one or more agreements.
// The Arc4u Foundation licenses this file to you under the MIT license.

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Arc4u.Cyphertool.Extensions;
using Arc4u.Diagnostics;
using Arc4u.Results;
using FluentResults;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.Logging;

namespace Arc4u.Cyphertool.Helpers
{
    internal enum KeyType
    {
        Rsa,
        Ec
    }

    /// <summary>
    /// The key to generate: a RSA key of <see cref="KeySize"/> bits or an EC key on the <see cref="Curve"/> (P-256, P-384 or P-521).
    /// </summary>
    internal sealed record KeyOptions(KeyType KeyType, int KeySize, string Curve);

    /// <summary>
    /// Create a root certificate (certificate authority) and certificates signed by it.
    /// The certificates are saved as a pfx file (with the chain), a pem certificate and an encrypted pem private key.
    /// </summary>
    internal class CreateCertificateHelper
    {
        public CreateCertificateHelper(CertificateHelper certificateHelper, ILogger<CreateCertificateHelper> logger)
        {
            _certificateHelper = certificateHelper;
            _logger = logger;
        }

        readonly CertificateHelper _certificateHelper;
        readonly ILogger<CreateCertificateHelper> _logger;

        public const int RootRsaKeySize = 4096;
        public const string RootCurve = "P-384";
        public const int RootYears = 10;
        public const int CertificateRsaKeySize = 3072;
        public const string CertificateCurve = "P-256";
        public const int CertificateYears = 2;

        // The Document Encryption extended key usage, needed by Windows to encrypt with a certificate (CMS).
        const string DocumentEncryptionOid = "1.3.6.1.4.1.311.80.1";

        #region Command line options

        /// <summary>
        /// Read the key type (-kt), key size (-ks) and curve (-c) options. The defaults depend on the certificate created (root or not).
        /// </summary>
        public static Result<KeyOptions> GetKeyOptions(CommandOption? keyTypeOption, CommandOption? keySizeOption, CommandOption? curveOption, int defaultKeySize, string defaultCurve)
        {
            var keyType = KeyType.Rsa;
            if (keyTypeOption is not null && keyTypeOption.HasValue())
            {
                if (!Enum.TryParse(keyTypeOption.Value(), true, out keyType))
                {
                    return Result.Fail($"{keyTypeOption.Value()} is not a valid key type! Use rsa or ec.");
                }
            }

            var keySize = defaultKeySize;
            if (keySizeOption is not null && keySizeOption.HasValue())
            {
                if (!int.TryParse(keySizeOption.Value(), out keySize) || keySize < 2048 || keySize % 1024 != 0)
                {
                    return Result.Fail($"{keySizeOption.Value()} is not a valid RSA key size! Use 2048, 3072 or 4096.");
                }
            }

            var curve = curveOption is not null && curveOption.HasValue() ? curveOption.Value()!.ToUpperInvariant() : defaultCurve;
            if (GetCurve(curve).IsFailed)
            {
                return Result.Fail($"{curve} is not a valid curve! Use P-256, P-384 or P-521.");
            }

            return Result.Ok(new KeyOptions(keyType, keySize, curve));
        }

        public static Result<int> GetYears(CommandOption? yearsOption, int defaultYears)
        {
            if (yearsOption is null || !yearsOption.HasValue())
            {
                return Result.Ok(defaultYears);
            }

            if (!int.TryParse(yearsOption.Value(), out var years) || years < 1 || years > 50)
            {
                return Result.Fail($"{yearsOption.Value()} is not a valid number of years (1 to 50)!");
            }

            return Result.Ok(years);
        }

        /// <summary>
        /// The password protecting the pfx file and the pem private key. Prompted (and confirmed) when not given.
        /// </summary>
        public static Result<string> GetNewPassword(CommandOption? passwordOption, string prompt)
        {
            if (passwordOption is not null && passwordOption.HasValue() && !string.IsNullOrEmpty(passwordOption.Value()))
            {
                return Result.Ok(passwordOption.Value()!);
            }

            var password = Prompt.GetPassword(prompt, ConsoleColor.DarkYellow);
            if (string.IsNullOrEmpty(password))
            {
                return Result.Fail("A password is needed to protect the private key!");
            }

            var confirm = Prompt.GetPassword("Confirm the password:", ConsoleColor.DarkYellow);
            if (!string.Equals(password, confirm, StringComparison.Ordinal))
            {
                return Result.Fail("The passwords don't match!");
            }

            return Result.Ok(password);
        }

        /// <summary>
        /// The folder where the files are saved: the current directory when not given or when it doesn't exist.
        /// </summary>
        public string GetFolder(CommandOption? folderOption)
        {
            var folder = Environment.CurrentDirectory;
            if (folderOption is not null && folderOption.HasValue())
            {
                if (Directory.Exists(folderOption.Value()))
                {
                    folder = folderOption.Value()!;
                }
                else
                {
                    _logger.Technical().LogWarning("The folder '{folder}' does not exist! The current directory will be used.", folderOption.Value()!);
                }
            }
            _logger.Technical().LogInformation("The certificates will be stored in the folder '{folder}'.", folder);

            return folder;
        }

        #endregion

        /// <summary>
        /// Create a self-signed root certificate, a certificate authority only allowed to sign end certificates (path length 0).
        /// </summary>
        public Result<X509Certificate2> CreateRoot(string subject, KeyOptions keyOptions, int years)
        {
            return GetSubject(subject)
                    .Bind(name => Result.Try(() =>
                    {
                        using var key = CreateKey(keyOptions);
                        var request = CreateRequest(name, key, GetHashAlgorithm(key));

                        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
                        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
                        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

                        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
                        return request.CreateSelfSigned(notBefore, notBefore.AddYears(years));
                    }));
        }

        /// <summary>
        /// Create a certificate signed by the <paramref name="issuer"/>, to encrypt and decrypt (and to be used for TLS server or client authentication).
        /// Its validity never goes beyond the one of the issuer.
        /// </summary>
        public Result<X509Certificate2> CreateSigned(X509Certificate2 issuer, string subject, KeyOptions keyOptions, int years, IEnumerable<string> subjectAlternativeNames)
        {
            var check = CheckIssuer(issuer);
            if (check.IsFailed)
            {
                return check;
            }

            return GetSubject(subject)
                    .Bind(name => Result.Try(() =>
                    {
                        using var issuerKey = (AsymmetricAlgorithm?)issuer.GetRSAPrivateKey() ?? issuer.GetECDsaPrivateKey()!;
                        using var key = CreateKey(keyOptions);
                        var request = CreateRequest(name, key, GetHashAlgorithm(issuerKey));

                        var keyUsages = key is RSA
                                            ? X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.DigitalSignature
                                            : X509KeyUsageFlags.KeyAgreement | X509KeyUsageFlags.DigitalSignature;

                        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
                        request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsages, true));
                        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection
                        {
                            new Oid("1.3.6.1.5.5.7.3.1"), // Server authentication.
                            new Oid("1.3.6.1.5.5.7.3.2"), // Client authentication.
                            new Oid(DocumentEncryptionOid)
                        }, false));
                        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
                        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false));

                        var sanBuilder = new SubjectAlternativeNameBuilder();
                        var hasSan = false;
                        foreach (var san in subjectAlternativeNames.Where(s => !string.IsNullOrWhiteSpace(s)))
                        {
                            if (IPAddress.TryParse(san, out var ip))
                            {
                                sanBuilder.AddIpAddress(ip);
                            }
                            else
                            {
                                sanBuilder.AddDnsName(san);
                            }
                            hasSan = true;
                        }
                        if (hasSan)
                        {
                            request.CertificateExtensions.Add(sanBuilder.Build());
                        }

                        var now = DateTimeOffset.UtcNow.AddMinutes(-5);
                        var notBefore = now < issuer.NotBefore ? new DateTimeOffset(issuer.NotBefore) : now;
                        var notAfter = now.AddYears(years);
                        if (notAfter > issuer.NotAfter)
                        {
                            notAfter = new DateTimeOffset(issuer.NotAfter);
                            _logger.Technical().LogWarning("The certificate validity is limited to the one of the issuer: {notAfter}.", notAfter);
                        }

                        var generator = issuerKey is RSA rsa
                                            ? X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1)
                                            : X509SignatureGenerator.CreateForECDsa((ECDsa)issuerKey);

                        using var certificate = request.Create(issuer.SubjectName, generator, notBefore, notAfter, RandomNumberGenerator.GetBytes(16));

                        return key is RSA rsaKey ? certificate.CopyWithPrivateKey(rsaKey) : certificate.CopyWithPrivateKey((ECDsa)key);
                    }));
        }

        /// <summary>
        /// Save the certificate in the <paramref name="folder"/>:
        /// - {CN}.pfx: the certificate with its private key (and the <paramref name="issuer"/> public certificate), encrypted with AES-256.
        /// - {CN}.pem: the public certificate.
        /// - {CN}.key.pem: the private key, encrypted with AES-256 (ENCRYPTED PRIVATE KEY).
        /// </summary>
        public Result Save(X509Certificate2 certificate, string password, string folder, X509Certificate2? issuer = null)
        {
            var commonName = certificate.GetCommonName();

            var pfx = Result.Try(() =>
            {
                var collection = new X509Certificate2Collection(certificate);
                if (issuer is not null)
                {
                    // The public certificate only: the issuer private key is never added.
                    collection.Add(X509CertificateLoader.LoadCertificate(issuer.RawData));
                }
                return collection.ExportPkcs12(Pkcs12ExportPbeParameters.Pbes2Aes256Sha256, password);
            });

            var pem = _certificateHelper.ConvertPublicKeyToPem(certificate);
            var key = _certificateHelper.ConvertEncryptedPrivateKeyToPem(certificate, password);

            var result = Result.Merge(pfx.ToResult(), pem.ToResult(), key.ToResult());
            if (result.IsFailed)
            {
                return result;
            }

            return Result.Try(() =>
            {
                var pfxFile = FileHelper.SaveFile(pfx.Value, folder, commonName, "{0}.pfx");
                _logger.Technical().LogInformation("Save the certificate with its private key to {name}", pfxFile);

                var pemFile = FileHelper.SaveFile(pem.Value, folder, commonName, "{0}.pem");
                _logger.Technical().LogInformation("Save public key to {name}", pemFile);

                var keyFile = FileHelper.SaveFile(key.Value, folder, commonName, "{0}.key.pem");
                _logger.Technical().LogInformation("Save encrypted private key to {name}", keyFile);
            });
        }

        /// <summary>
        /// The issuer must be a certificate authority with its private key.
        /// </summary>
        public static Result CheckIssuer(X509Certificate2 issuer)
        {
            if (!issuer.HasPrivateKey)
            {
                return Result.Fail($"The certificate '{issuer.Subject}' has no private key, it can't sign a certificate!");
            }

            var basicConstraints = issuer.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
            if (basicConstraints is null || !basicConstraints.CertificateAuthority)
            {
                return Result.Fail($"The certificate '{issuer.Subject}' is not a certificate authority!");
            }

            var keyUsage = issuer.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
            if (keyUsage is not null && !keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign))
            {
                return Result.Fail($"The certificate '{issuer.Subject}' is not allowed to sign certificates!");
            }

            if (issuer.GetRSAPublicKey() is null && issuer.GetECDsaPublicKey() is null)
            {
                return Result.Fail($"The certificate '{issuer.Subject}' doesn't have a RSA or an EC key.");
            }

            return Result.Ok();
        }

        /// <summary>
        /// A name like "My root" becomes "CN=My root", a distinguished name like "CN=My root, O=Arc4u" is kept.
        /// </summary>
        private static Result<X500DistinguishedName> GetSubject(string subject)
        {
            if (string.IsNullOrWhiteSpace(subject))
            {
                return Result.Fail("The subject is missing!");
            }

            var name = subject.Contains('=') ? subject : $"CN={subject}";
            return Result.Try(() => new X500DistinguishedName(name), ex => new Error($"'{subject}' is not a valid subject: {ex.Message}"));
        }

        private static Result<ECCurve> GetCurve(string curve) => curve.ToUpperInvariant() switch
        {
            "P-256" or "P256" or "NISTP256" => Result.Ok(ECCurve.NamedCurves.nistP256),
            "P-384" or "P384" or "NISTP384" => Result.Ok(ECCurve.NamedCurves.nistP384),
            "P-521" or "P521" or "NISTP521" => Result.Ok(ECCurve.NamedCurves.nistP521),
            _ => Result.Fail($"{curve} is not a valid curve!")
        };

        private static AsymmetricAlgorithm CreateKey(KeyOptions keyOptions)
            => keyOptions.KeyType == KeyType.Rsa
                ? RSA.Create(keyOptions.KeySize)
                : ECDsa.Create(GetCurve(keyOptions.Curve).Value);

        private static CertificateRequest CreateRequest(X500DistinguishedName subject, AsymmetricAlgorithm key, HashAlgorithmName hashAlgorithm)
            => key is RSA rsa
                ? new CertificateRequest(subject, rsa, hashAlgorithm, RSASignaturePadding.Pkcs1)
                : new CertificateRequest(subject, (ECDsa)key, hashAlgorithm);

        /// <summary>
        /// The hash used to sign follows the strength of the signing key.
        /// </summary>
        private static HashAlgorithmName GetHashAlgorithm(AsymmetricAlgorithm signingKey) => signingKey.KeySize switch
        {
            > 384 when signingKey is ECDsa => HashAlgorithmName.SHA512,
            > 256 when signingKey is ECDsa => HashAlgorithmName.SHA384,
            _ => HashAlgorithmName.SHA256
        };
    }
}
