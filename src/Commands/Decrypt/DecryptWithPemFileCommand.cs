// Licensed to the Arc4u Foundation under one or more agreements.
// The Arc4u Foundation licenses this file to you under the MIT license.

using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.Logging;

namespace Arc4u.Cyphertool.Commands
{
    internal class DecryptWithPemFileCommand
    {
        public DecryptWithPemFileCommand(ILogger<DecryptWithPemFileCommand> logger,
                                         DecryptTextCommand decryptTextCommand,
                                         DecryptFileCommand decryptFileCommand)
        {
            _logger = logger;
            _decryptTextCommand = decryptTextCommand;
            _decryptFileCommand = decryptFileCommand;
        }

        readonly DecryptFileCommand _decryptFileCommand;
        readonly ILogger<DecryptWithPemFileCommand> _logger;
        readonly DecryptTextCommand _decryptTextCommand;

        public void Configure(CommandLineApplication cmd)
        {
            cmd.FullName = nameof(DecryptWithPemFileCommand);
            cmd.Description = "DecryptFromPemCommand";
            cmd.HelpOption();

            // Argument
            var certifcate = cmd.Argument<string>("certificate", "The pem certificate file (.pem, .crt or .cer).");

            // Options
            var keyOption = cmd.Option("-k | --key", "The pem private key file.", CommandOptionType.SingleValue);
            var passwordOption = cmd.Option("-p | --password", "The password of the private key, when the pem key is encrypted.", CommandOptionType.SingleValue);

            cmd.Command("text", _decryptTextCommand.Configure);
            cmd.Command("file", _decryptFileCommand.Configure);

            cmd.OnExecute(() =>
            {
                cmd.ShowHelp();
                return 0;
            });
        }
    }
}
