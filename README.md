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

The Arc4u.Cyphertool is a dotnet tool working around the certificate and is able to perform 4 actions.

1) Encrypt a string or a file.
2) Decrypt the cypher text.
3) Extract certificate informations.
4) Create a root certificate and certificates signed by it.



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
arc4u.cyphertool extract pfx "C:\temp\devCert.pfx" -p password -ca -f "folder" | encrypt with  |                                         
                                                                               |                \ cert "devCert" -l LocalMachine -n My  
                                                                                       
                                                                               => optional

```

Read a certificate from a pfx file and extract the public, private and certificate authorities.

The private key, RSA or EC, is written as an unencrypted PKCS#8 pem (`-----BEGIN PRIVATE KEY-----`), the format read by openssl,
by `X509Certificate2.CreateFromPemFile` (and so by the Arc4u secret decryptor) and by `arc4u.cyphertool decrypt with pem`.
The version 1.0.x of the tool wrote an RSA key in the PKCS#1 format under a `PRIVATE KEY` header, which these readers reject: extract the key again with this version.

The reason for this is to avoid the openssl that doesn't exist natively on Windows but also to extract the certificate authorities.

This is useful when you want to use the certificate in dapr for some components like RabbitMQ for example
where you have to extract the public, the private key but also the certificate authorities.


```yaml
  - name: saslExternal
    value: true
  - name: clientCert
    value: |-
      -----BEGIN PUBLIC KEY-----
      [...]
      -----END PUBLIC KEY-----
  - name: clientKey
    value: |-
      -----BEGIN PRIVATE KEY-----
      [...]
      -----END PRIVATE KEY-----
  - name: caCert
    value: |-
      -----BEGIN PUBLIC KEY-----
      [...]
      -----END PUBLIC KEY-----
```

### From pem files

```console
arc4u.cyphertool extract pem "C:\temp\devCert.pem" -k "C:\temp\devCert.key.pem" -p password -f "folder"
```

Read a pem certificate and its private key, and write the public certificate (`{CN}.pem`) and the private key in clear (`{CN}.key.pem`, `-----BEGIN PRIVATE KEY-----`).
This decrypts the encrypted private key written by the `create` command (`-----BEGIN ENCRYPTED PRIVATE KEY-----`), like to store it in a Kubernetes secret.
When the key is encrypted and `-p` is not given, a prompt asks the password. Use another folder than the one of the encrypted key: an existing file is never overwritten.

```console
arc4u.cyphertool extract pem "./certs/My Certificate.pem" -k "./certs/My Certificate.key.pem" -f ./k8s
kubectl create secret tls my-certificate --cert="./k8s/My Certificate.pem" --key="./k8s/My Certificate.key.pem"
```

The private key in clear is not protected anymore: delete the file once it is stored in the secret.
A Kubernetes secret is only base64 encoded: enable the encryption at rest of the secrets and limit their access with RBAC.

### Openssl commands

Equivalent openssl commands to extract the public, private key from a pfx file.
#### Extract the public key

openssl pkcs12 -in devCert.pfx -clcerts -nokeys -out devCert.crt.pem


#### Extract the private key

openssl pkcs12 -in devCert.pfx -nocerts -out devCert.key.pem

## 4) Create

```console
                         / root  "CN=My Root CA" -p password -f "folder"
arc4u.cyphertool create |  cert  "CN=My Certificate" -ca "My Root CA.pfx" -cap root-password -p password -f "folder"
                         \ chain "CN=My Root CA" "CN=My Certificate" -rp root-password -p password -f "folder"
```

Create a private certificate authority and certificates signed by it, on Windows, macOS and Linux (no openssl needed):

- `create root`: a self-signed root certificate (CA, path length 0, only allowed to sign certificates), saved alone.
- `create cert`: a certificate signed by an existing root. The root is a pfx file, a pem file with its key (`-k`) or a certificate in the store or keychain (`-n`, `-l`).
- `create chain`: both at the same time.

Each certificate is saved in 3 files, an existing file is never overwritten:

| File | Content |
| --- | --- |
| `{CN}.pfx` | The certificate and its private key, protected by the password (PBES2, AES-256). The pfx of a signed certificate also contains the public root certificate. |
| `{CN}.pem` | The public certificate. |
| `{CN}.key.pem` | The private key, encrypted with the password (`-----BEGIN ENCRYPTED PRIVATE KEY-----`). |

The keys are RSA by default (4096 bits for the root, 3072 for a certificate), or EC with `-kt ec` (P-384 for the root, P-256 for a certificate).
A root is valid 10 years and a certificate 2 years by default (`-y`), a certificate never beyond its root.
A signed certificate can encrypt and decrypt with this tool (`encrypt with pem`, `decrypt with pfx` or `decrypt with pem -k`),
and can be used for TLS server or client authentication: add its dns names and ip addresses with `-san`.

When a password is not given, a prompt asks it twice.

To trust the root, add its `.pem` file to the trusted roots of each machine:

```console
# Windows (or -user for the current user)
certutil -addstore -f Root "My Root CA.pem"
# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "My Root CA.pem"
# Linux (Debian, Ubuntu)
sudo cp "My Root CA.pem" /usr/local/share/ca-certificates/my-root-ca.crt && sudo update-ca-certificates
```

Keep the root pfx and key files offline: only the certificates signed by it are deployed.

Complete documentation, execute

arc4u.cyphertool create --help

# Installing the tool.

## Globally.
dotnet tool install arc4u.cyphertool -g --version 2.0.0

You have to close and restart your terminal window to be able to run the Arc4u.Cyphertool tool.

to uninstall => dotnet tool uninstall Arc4u.Cyphertool -g

## In a specific folder.
Create a folder where you want to store the encryptor tool!  
For example C:\PRJ\Tools
If the folder is not yet part of the user environment path then run this in your terminal window:

setx path "%path%;C:\PRJ\Tools"

Close your terminal and then run this command:

dotnet tool install arc4u.cyphertool --tool-path c:\PRJ\Tools --version 2.0.0

There is no need to close your terminal because the path is already registered!

To uninstall => dotnet tool uninstall Arc4u.Cyphertool --tool-path c:\PRJ\Tools

To update => dotnet tool update arc4u.cyphertool --tool-path c:\PRJ\Tools --version 2.0.0
