// Licensed to the Arc4u Foundation under one or more agreements.
// The Arc4u Foundation licenses this file to you under the MIT license.

using Arc4u.Cyphertool.Helpers;
using Arc4u.Diagnostics;
using Arc4u.Results;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.Logging;

namespace Arc4u.Cyphertool.Commands;

internal class CreateRootCommand
{
    public CreateRootCommand(ILogger<CreateRootCommand> logger, CreateCertificateHelper createHelper)
    {
        _logger = logger;
        _createHelper = createHelper;
    }

    readonly ILogger<CreateRootCommand> _logger;
    readonly CreateCertificateHelper _createHelper;

    public void Configure(CommandLineApplication cmd)
    {
        cmd.FullName = nameof(CreateRootCommand);
        cmd.Description = "CreateRootCommand";
        cmd.HelpOption();

        // Argument
        var subject = cmd.Argument<string>("subject", "The subject of the root certificate, like \"CN=My Root CA, O=Company\".");

        // Options
        var passwordOption = cmd.Option("-p | --password", "The password protecting the pfx file and the private key.", CommandOptionType.SingleValue);
        var folderOption = cmd.Option("-f | --folder", "The folder to store the files.", CommandOptionType.SingleValue);
        var keyTypeOption = cmd.Option("-kt | --key-type", "The key type: rsa (default) or ec.", CommandOptionType.SingleValue);
        var keySizeOption = cmd.Option("-ks | --key-size", $"The RSA key size, default is {CreateCertificateHelper.RootRsaKeySize}.", CommandOptionType.SingleValue);
        var curveOption = cmd.Option("-c | --curve", $"The EC curve: P-256, P-384 or P-521, default is {CreateCertificateHelper.RootCurve}.", CommandOptionType.SingleValue);
        var yearsOption = cmd.Option("-y | --years", $"The validity in years, default is {CreateCertificateHelper.RootYears}.", CommandOptionType.SingleValue);

        cmd.OnExecute(() =>
        {
            var keyOptions = CreateCertificateHelper.GetKeyOptions(keyTypeOption, keySizeOption, curveOption, CreateCertificateHelper.RootRsaKeySize, CreateCertificateHelper.RootCurve).LogIfFailed();
            var years = CreateCertificateHelper.GetYears(yearsOption, CreateCertificateHelper.RootYears).LogIfFailed();
            if (keyOptions.IsFailed || years.IsFailed)
            {
                return -1;
            }

            var password = CreateCertificateHelper.GetNewPassword(passwordOption, "Root certificate password:").LogIfFailed();
            if (password.IsFailed)
            {
                return -1;
            }

            var root = _createHelper.CreateRoot(subject.Value!, keyOptions.Value, years.Value).LogIfFailed();
            if (root.IsFailed)
            {
                return -1;
            }

            using (root.Value)
            {
                _logger.Technical().LogInformation("The root certificate '{subject}' has been created, valid until {notAfter}.", root.Value.Subject, root.Value.NotAfter);

                return _createHelper.Save(root.Value, password.Value, _createHelper.GetFolder(folderOption)).LogIfFailed().IsSuccess ? 0 : -1;
            }
        });
    }
}
