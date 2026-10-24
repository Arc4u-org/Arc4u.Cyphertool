# Arc4u.Cyphertool

The Arc4u library provides a set of tools to encrypt and decrypt strings with an X509 certificate (X509Certificate2 in .NET).
Certificates with an RSA key or an EC key (P-256, P-384 or P-521) are supported.

## How the content is encrypted (Arc4u 9.0)

The algorithm is chosen from the key of the certificate.

With an **RSA** certificate, it depends on the size of the text:

- **Short text** (less than 191 bytes once encoded in UTF-8): the text is encrypted directly with the RSA key of the certificate (OAEP padding with SHA-256).
  The result is a single base64 string. The text is trimmed before it is encrypted.
- **Longer text**: RSA can only encrypt a few hundred bytes, so a symmetric key is used.
  A random 256 bits AES key is generated for each value and the text is encrypted with AES-GCM.
  Only the AES key is encrypted with the certificate (RSA, OAEP SHA-256). The nonce and the authentication tag are stored with the encrypted data,
  so a modified cypher text or a wrong key is detected when decrypting. The text is not trimmed.
  The result is made of two base64 parts separated by a dot: `encryptedKey.encryptedData`.

With an **EC** certificate, every text is encrypted with ECIES:

- A new EC key pair, on the curve of the certificate, is generated for each value.
- An ECDH key agreement between this ephemeral key and the certificate public key gives a shared secret, turned into a 256 bits AES key with HKDF-SHA256.
- The text is encrypted with AES-GCM. The text is not trimmed.
  The result is made of two base64 parts separated by a dot: `ephemeralPublicKey.encryptedData`.

A value must be decrypted with the certificate it was encrypted for: moving from an RSA to an EC certificate means encrypting the values again.

> [!NOTE]
> On Windows, the EC private key of a certificate is usually stored for signatures only and cannot do the key agreement needed to decrypt.
> The tool then copies the key, which must be exportable:
>
> - a pfx file is always loaded with an exportable key by the decrypt command;
> - pem files (`decrypt with pem cert.pem -k key.pem`) always work;
> - a certificate in the Windows certificate store must have been imported with an exportable private key.

The Arc4u.Configuration.Decryptor feature of the framework decrypts these values in a configuration section of an application.

> [!WARNING]
> **Values encrypted with Arc4u 8.x (8.2 and 8.3) are not all compatible with Arc4u 9.0.**
>
> From 8.2, Arc4u 8.x encrypted long texts with AES-CBC and stored the AES key **and** the initialization vector, each encrypted with the certificate,
> in three parts: `encryptedKey.encryptedIV.encryptedData`.
> Arc4u 9.0 (and this tool from version 2.0.0) only reads the two parts format: decrypting a three parts value fails with `Invalid encrypted string format`.
>
> - Short texts (a single base64 string) are encrypted the same way in both versions and are still decrypted.
> - Long texts (three parts) must be decrypted with the version 1.0.x of the tool (or an application using Arc4u 8.x) and encrypted again with this version
>   before the application moves to Arc4u 9.0.

## The tool

The Arc4u.Cyphertool is a dotnet tool working around the certificate and is able to perform 3 actions.

1) Encrypt a string or a file.
2) Decrypt the cypher text.
3) Extract certificate informations.

## 1) Encryption

```console
                               / pfx "C:\temp\devCert.pfx" -p password \
                              |                                         |   / text 'clear text' \
arc4u.cyphertool encrypt with |  pem "C:\temp\devCert.pem"              |  |                     | -o "file"
                              |                                         |   \ file "path"       /
                               \ cert "devCert" -l LocalMachine -n My  /

```

To encrypt with pem files, only the public certificate is needed (.pem, .crt or .cer).

Complete documentation, execute

arc4u.cyphertool encrypt --help

## 2) Decryption

```console

                               / pfx "C:\temp\devCert.pfx" -p password            \
                              |                                                    |   / text "cypher text" \
arc4u.cyphertool decrypt with | pem "C:\temp\devCert.pem" -k "C:\temp\devCert.key" |  |                      | -o "file"
                              |                                                    |   \ file "path"        /
                               \ cert "devCert" -l LocalMachine -n My             /


```

To decrypt with pem files, the private key is given with -k | --key. When the pem key is encrypted, its password is given with -p | --password.
Complete documentation, execute

arc4u.cyphertool decrypt --help

## 3) Extract

```console

                                                                                |                / pfx "C:\temp\devCert.pfx" -p password 
arc4u.cyphertool extract pfx "C:\temp\devCert.pfx" -p password -ca -f "folder"  | encrypt with  |                                         
                                                                                |                \ cert "devCert" -l LocalMachine -n My  
                                                                                       
                                                                                  => optional

```

Read a certificate from a pfx file or from the computer and extract the public private and certificate authorities.

The private key, RSA or EC, is written as an unencrypted PKCS#8 pem (`-----BEGIN PRIVATE KEY-----`), the format read by openssl,
by `X509Certificate2.CreateFromPemFile` (and so by the Arc4u secret decryptor) and by `arc4u.cyphertool decrypt with pem`.
The version 1.0.x of the tool wrote an RSA key in the PKCS#1 format under a `PRIVATE KEY` header, which these readers reject: extract the key again with this version.

