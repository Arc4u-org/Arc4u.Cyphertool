// Licensed to the Arc4u Foundation under one or more agreements.
// The Arc4u Foundation licenses this file to you under the MIT license.

using Arc4u.Diagnostics;
using Arc4u.Cyphertool;
using Arc4u.Results;
using Arc4u.Security.Cryptography;
using FluentResults;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.Logging;

namespace Arc4u.Cyphertool.Commands;



internal class EncryptTextCommand
{
    public EncryptTextCommand(ILogger<EncryptTextCommand> logger, CertificateHelper certificateHelper)
    {
        _logger = logger;
        _certificateHelper = certificateHelper;
    }

    readonly CertificateHelper _certificateHelper;
    readonly ILogger<EncryptTextCommand> _logger;

    /// <summary>
    /// Encrypt a text using a certificate.
    /// The certificate can be a file or a certificate store.
    /// It means that the parents are given this information back to the command.
    /// </summary>
    /// <param name="cmd"></param>
    public void Configure(CommandLineApplication cmd)
    {
        cmd.FullName = nameof(EncryptTextCommand);
        cmd.Description = "EncryptTextCommand";
        cmd.HelpOption();

        cmd.Argument<string>("text", "The text to encrypt.");
        var outputOption = cmd.Option("-o | --output", "The file to store the content.", CommandOptionType.SingleValue);

        cmd.OnExecute(() =>
        {
            var parent = cmd.Parent as CommandLineApplication;
            var certifcate = parent?.Arguments.FirstOrDefault(a => a.Name is not null && a.Name.Equals("certificate", StringComparison.OrdinalIgnoreCase));
            var storeName = parent?.Options.FirstOrDefault(a => a.LongName is not null && a.LongName.Equals("storename", StringComparison.OrdinalIgnoreCase));
            var storeLocation = parent?.Options.FirstOrDefault(a => a.LongName is not null && a.LongName.Equals("storelocation", StringComparison.OrdinalIgnoreCase));
            var password = parent?.Options.FirstOrDefault(a => a.LongName is not null && a.LongName.Equals("password", StringComparison.OrdinalIgnoreCase));
            var key = parent?.Options.FirstOrDefault(a => a.LongName is not null && a.LongName.Equals("key", StringComparison.OrdinalIgnoreCase));

            if (null == certifcate?.Value)
            {
                _logger.LogError("The certificate is missing!");
                return;
            }

            var textArgument = cmd.Arguments.FirstOrDefault(a => a.Name is not null && a.Name.Equals("text", StringComparison.OrdinalIgnoreCase));

            if (textArgument is null)
            {
                _logger.Technical().LogError("No text command has been given!");
                cmd.ShowHelp();
                return;
            }

            if (textArgument.Value is null)
            {
                _logger.Technical().LogError("No text argument has been given!");
                cmd.ShowHelp();
                return;
            }

            _certificateHelper.GetCertificate(certifcate.Value, password?.Value(), storeName?.Value(), storeLocation?.Value(), key: key?.Value())
                              .LogIfFailed()
                              .OnSuccessNotNull(x509 =>
                              {
                                  Result.Try(() => x509.Encrypt(textArgument.Value))
                                  .LogIfFailed()
                                  .OnSuccessNotNull(encrypted =>
                                  {
                                      if (outputOption.HasValue())
                                      {
                                          try
                                          {
                                              File.WriteAllText(outputOption.Value()!, encrypted);
                                              _logger.LogInformation($"The content has been saved in the file '{outputOption.Value()}'");
                                          }
                                          catch (Exception ex)
                                          {
                                              _logger.LogError(ex.Message);
                                          }
                                      }
                                      else
                                      {
                                          Console.WriteLine();
                                          Console.Write("The encrypted text of ");
                                          Console.Write(textArgument.Value);
                                          Console.WriteLine(" is:");
                                          Console.ForegroundColor = ConsoleColor.Yellow;
                                          Console.WriteLine(encrypted);
                                          Console.ResetColor();
                                      }
                                  });
                              });
        });
    }
}
