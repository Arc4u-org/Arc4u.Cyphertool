// Licensed to the Arc4u Foundation under one or more agreements.
// The Arc4u Foundation licenses this file to you under the MIT license.

using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using FluentResults;

namespace Arc4u.Cyphertool.Extensions
{
    internal static class X509Certificate2Ext
    {
        private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);

        public static string GetCommonName(this X509Certificate2 x509)
        {
            string pattern = @"CN=([^,]+)";
            try
            {
                Match match = Regex.Match(x509.Subject, pattern, RegexOptions.None, RegexTimeout);
                if (match.Success)
                {
                    return match.Groups[1].Value;
                }
            }
            catch (RegexMatchTimeoutException)
            {
                // Fall through to the friendly name.
            }

            return x509.FriendlyName ?? "Unknown";
        }
    }
}
