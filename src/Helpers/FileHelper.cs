// Licensed to the Arc4u Foundation under one or more agreements.
// The Arc4u Foundation licenses this file to you under the MIT license.

namespace Arc4u.Cyphertool.Helpers
{
    internal static class FileHelper
    {
        /// <summary>
        /// Save a text file named from <paramref name="pattern"/> and <paramref name="commonName"/>.
        /// An existing file is never overwritten: a (1), (2)... suffix is added to the name.
        /// </summary>
        public static string SaveFile(string content, string folder, string commonName, string pattern)
            => SaveFile(folder, commonName, pattern, fileName => File.WriteAllText(fileName, content));

        public static string SaveFile(byte[] content, string folder, string commonName, string pattern)
            => SaveFile(folder, commonName, pattern, fileName => File.WriteAllBytes(fileName, content));

        private static string SaveFile(string folder, string commonName, string pattern, Action<string> write)
        {
            commonName = string.Concat(commonName.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c));

            var fileName = Path.Combine(folder, string.Format(pattern, commonName));
            var idx = 1;
            while (File.Exists(fileName))
            {
                fileName = Path.Combine(folder, string.Format(pattern, $"{commonName}({idx++})"));
            }
            write(fileName);

            return fileName;
        }
    }
}
