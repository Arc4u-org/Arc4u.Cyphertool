// Licensed to the Arc4u Foundation under one or more agreements.
// The Arc4u Foundation licenses this file to you under the MIT license.

using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.Logging;

namespace Arc4u.Cyphertool.Commands;

internal class EncryptWithCommand
{
    public EncryptWithCommand(ILogger<EncryptWithCommand> logger,
                              EncryptWithCertificateStoreCommand fromStoreCommand,
                              EncryptWithPfxFileCommand fromPfxFileCommand,
                              EncryptWithPemFileCommand fromPemFileCommand)
    {
        _logger = logger;
        _fromStoreCommand = fromStoreCommand;
        _fromPfxFileCommand = fromPfxFileCommand;
        _fromPemFileCommand = fromPemFileCommand;
    }

    readonly EncryptWithPfxFileCommand _fromPfxFileCommand;
    readonly EncryptWithPemFileCommand _fromPemFileCommand;
    readonly EncryptWithCertificateStoreCommand _fromStoreCommand;
    readonly ILogger<EncryptWithCommand> _logger;

    const string pfxFileCommand = "pfx";
    const string pemFileCommand = "pem";
    public void Configure(CommandLineApplication cmd)
    {
        cmd.FullName = nameof(EncryptWithCommand);
        cmd.Description = "EncryptCommand";
        cmd.HelpOption();

        var certCommand = cmd.Command("certificate-store", _fromStoreCommand.Configure);
        certCommand.AddName("cert");
        certCommand.AddName("keychain");

        cmd.Command(pfxFileCommand, _fromPfxFileCommand.Configure);
        cmd.Command(pemFileCommand, _fromPemFileCommand.Configure);

        cmd.OnExecute(() =>
        {
            cmd.ShowHelp();
            return 0;
        });
    }

}
