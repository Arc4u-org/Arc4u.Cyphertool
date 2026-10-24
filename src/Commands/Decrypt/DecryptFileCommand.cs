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

internal class DecryptFileCommand
{
    public DecryptFileCommand(ILogger<DecryptFileCommand> logger, CertificateHelper certificateHelper)
    {
        _logger = logger;
        _certificateHelper = certificateHelper;
    }

    readonly CertificateHelper _certificateHelper;
    readonly ILogger<DecryptFileCommand> _logger;

    /// <summary>
    /// Encrypt a text using a certificate.
    /// The certificate can be a file or a certificate store.
    /// It means that the parents are given this information back to the command.
    /// </summary>
    /// <param name="cmd"></param>
    public void Configure(CommandLineApplication cmd)
    {
        cmd.FullName = nameof(DecryptFileCommand);
        cmd.Description = "DecryptFileCommand";
        cmd.HelpOption();

        cmd.Argument<string>("file", "The file to encrypt.");
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

            var fileArgument = cmd.Arguments.FirstOrDefault(a => a.Name is not null && a.Name.Equals("file", StringComparison.OrdinalIgnoreCase));

            if (fileArgument is null)
            {
                _logger.Technical().LogError("No file command has been given!");
                cmd.ShowHelp();
                return;
            }

            if (fileArgument.Value is null)
            {
                _logger.Technical().LogError("No file argument has been given!");
                cmd.ShowHelp();
                return;
            }

            if (!File.Exists(fileArgument.Value))
            {
                _logger.Technical().LogError("The file {file} doesn't exist.", fileArgument.Value);
                return;
            }


            _certificateHelper.GetCertificate(certifcate.Value, password?.Value(), storeName?.Value(), storeLocation?.Value(), privKeyIsExportable: true, key: key?.Value())
                              .LogIfFailed()
                              .OnSuccessNotNull(x509 =>
                              {
                                  if (!x509.HasPrivateKey)
                                  {
                                      _logger.Technical().LogError("The certificate {subject} has no private key. With a pem certificate, give the private key with -k | --key.", x509.Subject);
                                      return;
                                  }

                                  Result.Try(() => x509.Decrypt(File.ReadAllText(fileArgument.Value)))
                                  .LogIfFailed()
                                  .OnSuccessNotNull(text =>
                                  {
                                      if (outputOption.HasValue())
                                      {
                                          try
                                          {
                                              File.WriteAllText(outputOption.Value()!, text);
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
                                          Console.WriteLine("The decrypted text is:");
                                          Console.ForegroundColor = ConsoleColor.Yellow;
                                          Console.WriteLine(text);
                                          Console.ResetColor();
                                      }
                                  });
                              });
        });
    }
}
