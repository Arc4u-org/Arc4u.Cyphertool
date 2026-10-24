// Licensed to the Arc4u Foundation under one or more agreements.
// The Arc4u Foundation licenses this file to you under the MIT license.

using Arc4u.Cyphertool.Helpers;
using Arc4u.Diagnostics;
using Arc4u.Results;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.Logging;

namespace Arc4u.Cyphertool.Commands;

internal class CreateCertificateCommand
{
    public CreateCertificateCommand(ILogger<CreateCertificateCommand> logger, CertificateHelper certificateHelper, CreateCertificateHelper createHelper)
    {
        _logger = logger;
        _certificateHelper = certificateHelper;
        _createHelper = createHelper;
    }

    readonly ILogger<CreateCertificateCommand> _logger;
    readonly CertificateHelper _certificateHelper;
    readonly CreateCertificateHelper _createHelper;

    public void Configure(CommandLineApplication cmd)
    {
        cmd.FullName = nameof(CreateCertificateCommand);
        cmd.Description = "CreateCertificateCommand";
        cmd.HelpOption();

        // Argument
        var subject = cmd.Argument<string>("subject", "The subject of the certificate, like \"CN=My Certificate, O=Company\".");

        // The root certificate signing the new one.
        var caOption = cmd.Option("-ca | --certificate-authority", "The root certificate: a pfx file, a pem file (with -k) or the friendly name of a certificate in the store or keychain.", CommandOptionType.SingleValue);
        var caPasswordOption = cmd.Option("-cap | --ca-password", "The password of the root pfx file or of its encrypted pem private key.", CommandOptionType.SingleValue);
        var caKeyOption = cmd.Option("-k | --key", "The pem private key file of the root pem certificate.", CommandOptionType.SingleValue);
        var storeNameOption = cmd.Option("-n | --storename", "The name of the folder where the root certificate is stored in a Keychain or Certificate Store.", CommandOptionType.SingleValue);
        var storeLocationOption = cmd.Option("-l | --storelocation", "The location where the root certificate is stored in a Keychain or Certificate Store. Like on Windows: CurrentUser or LocalMachine. Default is CurrentUser!", CommandOptionType.SingleValue);

        // The new certificate.
        var passwordOption = cmd.Option("-p | --password", "The password protecting the pfx file and the private key.", CommandOptionType.SingleValue);
        var folderOption = cmd.Option("-f | --folder", "The folder to store the files.", CommandOptionType.SingleValue);
        var keyTypeOption = cmd.Option("-kt | --key-type", "The key type: rsa (default) or ec.", CommandOptionType.SingleValue);
        var keySizeOption = cmd.Option("-ks | --key-size", $"The RSA key size, default is {CreateCertificateHelper.CertificateRsaKeySize}.", CommandOptionType.SingleValue);
        var curveOption = cmd.Option("-c | --curve", $"The EC curve: P-256, P-384 or P-521, default is {CreateCertificateHelper.CertificateCurve}.", CommandOptionType.SingleValue);
        var yearsOption = cmd.Option("-y | --years", $"The validity in years, default is {CreateCertificateHelper.CertificateYears}.", CommandOptionType.SingleValue);
        var sanOption = cmd.Option("-san | --subject-alternative-name", "A dns name or an ip address of the certificate, can be repeated.", CommandOptionType.MultipleValue);

        cmd.OnExecute(() =>
        {
            if (!caOption.HasValue())
            {
                _logger.Technical().LogError("The root certificate is missing! Give it with -ca | --certificate-authority.");
                return -1;
            }

            var keyOptions = CreateCertificateHelper.GetKeyOptions(keyTypeOption, keySizeOption, curveOption, CreateCertificateHelper.CertificateRsaKeySize, CreateCertificateHelper.CertificateCurve).LogIfFailed();
            var years = CreateCertificateHelper.GetYears(yearsOption, CreateCertificateHelper.CertificateYears).LogIfFailed();
            if (keyOptions.IsFailed || years.IsFailed)
            {
                return -1;
            }

            var root = _certificateHelper.GetCertificate(caOption.Value()!, caPasswordOption.Value(), storeNameOption.Value(), storeLocationOption.Value(), prompt: "Root certificate password:", key: caKeyOption.Value())
                                         .LogIfFailed();
            if (root.IsFailed)
            {
                return -1;
            }

            using (root.Value)
            {
                _logger.Technical().LogInformation("The root certificate '{subject}' has been loaded!", root.Value.Subject);

                var check = CreateCertificateHelper.CheckIssuer(root.Value).LogIfFailed();
                if (check.IsFailed)
                {
                    return -1;
                }

                var password = CreateCertificateHelper.GetNewPassword(passwordOption, "Certificate password:").LogIfFailed();
                if (password.IsFailed)
                {
                    return -1;
                }

                var certificate = _createHelper.CreateSigned(root.Value, subject.Value!, keyOptions.Value, years.Value, sanOption.Values!).LogIfFailed();
                if (certificate.IsFailed)
                {
                    return -1;
                }

                using (certificate.Value)
                {
                    _logger.Technical().LogInformation("The certificate '{subject}' has been created, valid until {notAfter}.", certificate.Value.Subject, certificate.Value.NotAfter);

                    return _createHelper.Save(certificate.Value, password.Value, _createHelper.GetFolder(folderOption), root.Value).LogIfFailed().IsSuccess ? 0 : -1;
                }
            }
        });
    }
}
