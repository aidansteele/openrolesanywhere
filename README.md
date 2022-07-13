# `openrolesanywhere`

`openrolesanywhere` is an open-source client for [AWS IAM Roles Anywhere][aws-docs].
**Consider this project to be a proof-of-concept**. It's unlikely something that you
would actually use in production, even if it technically works. It was more for
my own education.

## What and why?

The [official client][aws-client] works, but has a few short-comings IMO. It's
not open source and it requires you to store private keys in plaintext on the
filesystem. **This project lets you use private keys stored in an SSH agent.** 
This is more flexible - and more secure if you use something like [Secretive][secretive]
which stores unexportable keys in the macOS Secure Enclave hardware.

## Usage

First, we're going to use an [AWS KMS asymmetric key][kms] as the private key
for our certificate authority[1]. Look at [`key.yml`](/key.yml) for an example
KMS key to create.

Once you have the key ARN, we run the following command. It will create a new
self-signed certificate (using the private key stored in KMS) and register it
in Roles Anywhere as a trust anchor. The certificate will be stored in 
`~/.config/openrolesanywhere/ca.pem`.

```
openrolesanywhere admin create-ca \
  --name NameOfYourChoiceForTrustAnchorInRolesAnywhere \ 
  --kms-key-id fecbd22d-c110-beef-cafe-7986a49ee7f0 \
  --validity-duration 8760h \
  --serial-number 12345 \
  --common-name whateverYouWant \
  [--organization org] \
  [--organization-unit unit] \
  [--country country] \
  [--locality locality] \
  [--province province] \
  [--street-address addr] \
  [--postal-code 1234]
```

Next, we create a profile. As best I can tell, this is a mapping from trust
anchors to IAM roles. Run this:

```
openrolesanywhere admin create-profile \
  --name SomeProfileName \
  --session-duration 3600s \
  --role-arn arn:aws:iam::012345678912:role/SomeRoleName \
  --role-arn arn:aws:iam::012345678912:role/AnotherRoleName
```

Now we can start requesting certificates. First run `ssh-add -l` to get a list
of fingerprints for the keys stored in your SSH agent. Mine looks like this:

```
256 SHA256:KBsk40KWP/UDoYoiFnpFk+z5JnMInwsrAFONMLrlryc ecdsa-sha2-nistp256 (ECDSA)
256 SHA256:z/A9nNwdk1ZTmwtdrAlF2JQnGS8C7V3ozOPMt5lgqBk ecdsa-sha2-nistp256 (ECDSA)
```

I want to use that second key, so I'll run the following command:

```
openrolesanywhere request-certificate \
  --ssh-fingerprint SHA256:z/A9nNwdk1ZTmwtdrAlF2JQnGS8C7V3ozOPMt5lgqBk
```

That prints out the following:

```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYsYssxy2c9hesBTw0b5fNvoMzr8H
OMuqJ7OzWyLAqdPtcryZ8qHuZWAdd68z4A20u/quPhomJEa7ZGlzfU672A==
-----END PUBLIC KEY-----
```

Now we can send that to our administrator (which is probably us) and they will
run:

```
openrolesanywhere admin accept-request \
  --request-file path/to/above/publickey.pem \ 
  --validity-duration 8760h \
  --serial-number 67890 \
  --common-name nameOfTheEnduser \
  [--organization org] \
  [--organization-unit unit] \
  [--country country] \
  [--locality locality] \
  [--province province] \
  [--street-address addr] \
  [--postal-code 1234]
```

That will print out a certificate to the terminal, like this one:

```
-----BEGIN CERTIFICATE-----
MIICoDCCAkWgAwIBAgIDAQkyMAoGCCqGSM49BAMCMHIxCTAHBgNVBAYTADEJMAcG
A1UECBMAMQkwBwYDVQQHEwAxCTAHBgNVBAkTADEJMAcGA1UEERMAMQ4wDAYDVQQK
EwVteW9yZzEJMAcGA1UECxMAMQ4wDAYDVQQDEwVvcmFjYTEOMAwGA1UEBRMFMTIz
NDUwHhcNMjIwNzE0MDQ1NTMzWhcNMjMwNzE0MDQ1NTMzWjAyMQ4wDAYDVQQKEwVt
eW9yZzEQMA4GA1UEAxMHZW5kdXNlcjEOMAwGA1UEBRMFNjc4OTAwWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAARixiyzHLZz2F6wFPDRvl82+gzOvwc4y6ons7NbIsCp
0+1yvJnyoe5lYB13rzPgDbS7+q4+GiYkRrtkaXN9TrvYo4IBCDCCAQQwDgYDVR0P
AQH/BAQDAgeAMB8GA1UdIwQYMBaAFOtkd1bCuMx15rQyMunITV9hKFFnMIHQBgNV
HREEgcgwgcWGXmFybjphd3M6cm9sZXNhbnl3aGVyZTphcC1zb3V0aGVhc3QtMjo2
MDc0ODE1ODE1OTY6cHJvZmlsZS9hZmViMTgzZS02OGUyLTQyMWEtYmVlNC01NTVh
MGI0NDc5NDaGY2Fybjphd3M6cm9sZXNhbnl3aGVyZTphcC1zb3V0aGVhc3QtMjo2
MDc0ODE1ODE1OTY6dHJ1c3QtYW5jaG9yL2Y5MjM2ZTVhLWZkOTMtNDU4Ny1iZmJj
LWFhODk2Y2E0ZWM1MjAKBggqhkjOPQQDAgNJADBGAiEA2MHoibJqVMyLUzcpBkY/
OyPX0k/nQ2Tqz7ElU7xSUq4CIQCJBHcVKwU0F2w8g0pecrIG/WhA0cO+xRl1VOz8
TcS7MQ==
-----END CERTIFICATE-----
```

We tell the end-user (again, probably ourselves) to store that file in
`~/.config/openrolesanywhere/mycert.pem`. Once they've done that, they can
now configure the AWS CLI and SDKs to use it to retrieve AWS credentials.

To do that, the end-user adds this to their `~/.aws/config`:

```
[profile example]
credential_process = openrolesanywhere credential-process --name mycert --role-arn arn:aws:iam::012345678912:role/SomeRoleName
region = ap-southeast-2
```

Now running `aws sts get-caller-identity --profile example` will work! Likewise,
the AWS SDK in most programs should work out of the box by setting an environment
variable like `AWS_PROFILE=example`.

## Tidbits

In an ideal world, there's all sorts of features you might expect to see in a
fully-featured production version of this:

* Support for [PKCS#11][pkcs11] to support smart cards
* Support for keys stored in [TPMs][tpm] 
* Yubikeys (are probably covered by one of the above?)
* A SigV4 implementation that isn't copy-pasted and edited from the AWS SDK
* Documentation for `rolesanywhere:CreateSession`

[1]: I wanted to use an SSH agent for the certificate authority, but this wasn't
possible out of the box with the Go stdlib - and I didn't want to sink too much
time into a PoC.

[aws-docs]: https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html
[aws-client]: https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html
[secretive]: https://github.com/maxgoedjen/secretive
[kms]: https://docs.aws.amazon.com/kms/latest/developerguide/symmetric-asymmetric.html
[pkcs11]: https://en.wikipedia.org/wiki/PKCS_11
[tpm]: https://en.wikipedia.org/wiki/Trusted_Platform_Module
