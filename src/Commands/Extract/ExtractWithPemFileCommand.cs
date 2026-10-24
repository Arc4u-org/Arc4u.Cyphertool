// Licensed to the Arc4u Foundation under one or more agreements.
// The Arc4u Foundation licenses this file to you under the MIT license.

using Arc4u.Cyphertool.Helpers;
using Arc4u.Diagnostics;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.Logging;

namespace Arc4u.Cyphertool.Commands
{
    /// <summary>
    /// Extract the public certificate and the private key in clear from a pem certificate and its (encrypted) pem private key.
    /// </summary>
    internal class ExtractWithPemFileCommand
    {
        public ExtractWithPemFileCommand(ILogger<ExtractWithPemFileCommand> logger, ExtractCertificateHelper extract)
        {
            _logger = logger;
            _extract = extract;
        }

        readonly ExtractCertificateHelper _extract;
        readonly ILogger<ExtractWithPemFileCommand> _logger;

        public void Configure(CommandLineApplication cmd)
        {
            cmd.FullName = nameof(ExtractWithPemFileCommand);
            cmd.Description = "ExtractPemCommand";
            cmd.HelpOption();

            // Argument
            var certifcate = cmd.Argument<string>("certificate", "The pem certificate file (.pem, .crt or .cer).");

            // Options
            var keyOption = cmd.Option("-k | --key", "The pem private key file.", CommandOptionType.SingleValue);
            var passwordOption = cmd.Option("-p | --password", "The password of the private key, when the pem key is encrypted.", CommandOptionType.SingleValue);
            var folderOption = cmd.Option("-f | --folder", "The folder to store the keys.", CommandOptionType.SingleValue);

            cmd.OnExecute(() =>
            {
                if (!keyOption.HasValue())
                {
                    _logger.Technical().LogError("The private key is missing! Give it with -k | --key.");
                    return -1;
                }

                return _extract.ExtractCertificatePems(certifcate, passwordOption, folderOption, null, keyOption: keyOption);
            });
        }
    }
}
