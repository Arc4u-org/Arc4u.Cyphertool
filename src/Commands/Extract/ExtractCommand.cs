// Licensed to the Arc4u Foundation under one or more agreements.
// The Arc4u Foundation licenses this file to you under the MIT license.

using Arc4u.Cyphertool.Extensions;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.Logging;

namespace Arc4u.Cyphertool.Commands;

internal class ExtractCommand
{
    public ExtractCommand(ExtractWithPfxFileCommand pfxFileCommand, ExtractWithPemFileCommand pemFileCommand)
    {
        _pfxFileCommand = pfxFileCommand;
        _pemFileCommand = pemFileCommand;
    }

    readonly ExtractWithPfxFileCommand _pfxFileCommand;
    readonly ExtractWithPemFileCommand _pemFileCommand;

    public void Configure(CommandLineApplication cmd)
    {
        cmd.FullName = nameof(ExtractCommand);
        cmd.Description = "ExtractCommand";
        cmd.HelpOption();

        cmd.Command("pfx", _pfxFileCommand.Configure);
        cmd.Command("pem", _pemFileCommand.Configure);

        cmd.OnExecute(() =>
        {
            cmd.ShowHelp();
            return 0;
        });
    }


}
