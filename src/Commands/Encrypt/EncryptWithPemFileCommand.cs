// Licensed to the Arc4u Foundation under one or more agreements.
// The Arc4u Foundation licenses this file to you under the MIT license.

using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.Logging;

namespace Arc4u.Cyphertool.Commands
{
    internal class EncryptWithPemFileCommand
    {
        public EncryptWithPemFileCommand(ILogger<EncryptWithPemFileCommand> logger,
                                         EncryptTextCommand encryptTextCommand,
                                         EncryptFileCommand encryptFileCommand)
        {
            _logger = logger;
            _textEncryptor = encryptTextCommand;
            _encryptFileCommand = encryptFileCommand;
        }

        readonly EncryptFileCommand _encryptFileCommand;
        readonly ILogger<EncryptWithPemFileCommand> _logger;
        readonly EncryptTextCommand _textEncryptor;

        public void Configure(CommandLineApplication cmd)
        {
            cmd.FullName = nameof(EncryptWithPemFileCommand);
            cmd.Description = "EncryptFromPemCommand";
            cmd.HelpOption();

            // Argument: only the public certificate is needed to encrypt.
            var certifcate = cmd.Argument<string>("certificate", "The pem certificate file (.pem, .crt or .cer).");

            cmd.Command("text", _textEncryptor.Configure);
            cmd.Command("file", _encryptFileCommand.Configure);

            cmd.OnExecute(() =>
            {
                cmd.ShowHelp();
                return 0;
            });
        }
    }
}
