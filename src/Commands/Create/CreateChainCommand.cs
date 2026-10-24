// Licensed to the Arc4u Foundation under one or more agreements.
// The Arc4u Foundation licenses this file to you under the MIT license.

using Arc4u.Cyphertool.Helpers;
using Arc4u.Diagnostics;
using Arc4u.Results;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.Logging;

namespace Arc4u.Cyphertool.Commands;

/// <summary>
/// Create a root certificate and a certificate signed by it, in one go.
/// </summary>
internal class CreateChainCommand
{
    public CreateChainCommand(ILogger<CreateChainCommand> logger, CreateCertificateHelper createHelper)
    {
        _logger = logger;
        _createHelper = createHelper;
    }

    readonly ILogger<CreateChainCommand> _logger;
    readonly CreateCertificateHelper _createHelper;

    public void Configure(CommandLineApplication cmd)
    {
        cmd.FullName = nameof(CreateChainCommand);
        cmd.Description = "CreateChainCommand";
        cmd.HelpOption();

        // Arguments
        var rootSubject = cmd.Argument<string>("root-subject", "The subject of the root certificate, like \"CN=My Root CA, O=Company\".");
        var subject = cmd.Argument<string>("subject", "The subject of the certificate, like \"CN=My Certificate, O=Company\".");

        // Options
        var rootPasswordOption = cmd.Option("-rp | --root-password", "The password protecting the root pfx file and its private key.", CommandOptionType.SingleValue);
        var rootYearsOption = cmd.Option("-ry | --root-years", $"The validity of the root certificate in years, default is {CreateCertificateHelper.RootYears}.", CommandOptionType.SingleValue);
        var passwordOption = cmd.Option("-p | --password", "The password protecting the certificate pfx file and its private key.", CommandOptionType.SingleValue);
        var yearsOption = cmd.Option("-y | --years", $"The validity of the certificate in years, default is {CreateCertificateHelper.CertificateYears}.", CommandOptionType.SingleValue);
        var folderOption = cmd.Option("-f | --folder", "The folder to store the files.", CommandOptionType.SingleValue);
        var keyTypeOption = cmd.Option("-kt | --key-type", "The key type of both certificates: rsa (default) or ec.", CommandOptionType.SingleValue);
        var keySizeOption = cmd.Option("-ks | --key-size", $"The RSA key size of the certificate, default is {CreateCertificateHelper.CertificateRsaKeySize} ({CreateCertificateHelper.RootRsaKeySize} for the root).", CommandOptionType.SingleValue);
        var curveOption = cmd.Option("-c | --curve", $"The EC curve of the certificate: P-256, P-384 or P-521, default is {CreateCertificateHelper.CertificateCurve} ({CreateCertificateHelper.RootCurve} for the root).", CommandOptionType.SingleValue);
        var sanOption = cmd.Option("-san | --subject-alternative-name", "A dns name or an ip address of the certificate, can be repeated.", CommandOptionType.MultipleValue);

        cmd.OnExecute(() =>
        {
            // The root keeps its own (stronger) default key size and curve, only the key type is shared.
            var rootKeyOptions = CreateCertificateHelper.GetKeyOptions(keyTypeOption, null, null, CreateCertificateHelper.RootRsaKeySize, CreateCertificateHelper.RootCurve).LogIfFailed();
            var keyOptions = CreateCertificateHelper.GetKeyOptions(keyTypeOption, keySizeOption, curveOption, CreateCertificateHelper.CertificateRsaKeySize, CreateCertificateHelper.CertificateCurve).LogIfFailed();
            var rootYears = CreateCertificateHelper.GetYears(rootYearsOption, CreateCertificateHelper.RootYears).LogIfFailed();
            var years = CreateCertificateHelper.GetYears(yearsOption, CreateCertificateHelper.CertificateYears).LogIfFailed();
            if (rootKeyOptions.IsFailed || keyOptions.IsFailed || rootYears.IsFailed || years.IsFailed)
            {
                return -1;
            }

            var rootPassword = CreateCertificateHelper.GetNewPassword(rootPasswordOption, "Root certificate password:").LogIfFailed();
            if (rootPassword.IsFailed)
            {
                return -1;
            }

            var password = CreateCertificateHelper.GetNewPassword(passwordOption, "Certificate password:").LogIfFailed();
            if (password.IsFailed)
            {
                return -1;
            }

            var root = _createHelper.CreateRoot(rootSubject.Value!, rootKeyOptions.Value, rootYears.Value).LogIfFailed();
            if (root.IsFailed)
            {
                return -1;
            }

            using (root.Value)
            {
                _logger.Technical().LogInformation("The root certificate '{subject}' has been created, valid until {notAfter}.", root.Value.Subject, root.Value.NotAfter);

                var certificate = _createHelper.CreateSigned(root.Value, subject.Value!, keyOptions.Value, years.Value, sanOption.Values!).LogIfFailed();
                if (certificate.IsFailed)
                {
                    return -1;
                }

                using (certificate.Value)
                {
                    _logger.Technical().LogInformation("The certificate '{subject}' has been created, valid until {notAfter}.", certificate.Value.Subject, certificate.Value.NotAfter);

                    var folder = _createHelper.GetFolder(folderOption);
                    var saveRoot = _createHelper.Save(root.Value, rootPassword.Value, folder).LogIfFailed();
                    var save = _createHelper.Save(certificate.Value, password.Value, folder, root.Value).LogIfFailed();

                    return saveRoot.IsSuccess && save.IsSuccess ? 0 : -1;
                }
            }
        });
    }
}
