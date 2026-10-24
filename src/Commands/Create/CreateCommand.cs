// Licensed to the Arc4u Foundation under one or more agreements.
// The Arc4u Foundation licenses this file to you under the MIT license.

using McMaster.Extensions.CommandLineUtils;

namespace Arc4u.Cyphertool.Commands;

internal class CreateCommand
{
    public CreateCommand(CreateRootCommand rootCommand,
                         CreateCertificateCommand certificateCommand,
                         CreateChainCommand chainCommand)
    {
        _rootCommand = rootCommand;
        _certificateCommand = certificateCommand;
        _chainCommand = chainCommand;
    }

    readonly CreateRootCommand _rootCommand;
    readonly CreateCertificateCommand _certificateCommand;
    readonly CreateChainCommand _chainCommand;

    public void Configure(CommandLineApplication cmd)
    {
        cmd.FullName = nameof(CreateCommand);
        cmd.Description = "CreateCommand";
        cmd.HelpOption();

        cmd.Command("root", _rootCommand.Configure);
        cmd.Command("cert", _certificateCommand.Configure);
        cmd.Command("chain", _chainCommand.Configure);

        cmd.OnExecute(() =>
        {
            cmd.ShowHelp();
            return 0;
        });
    }
}
