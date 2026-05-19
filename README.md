# age-plugin-fido2-hmac

Encrypt and decrypt [age](https://github.com/FiloSottile/age) files with FIDO2
security keys that support the `hmac-secret` extension.

## Status

This project can be considered experimental in its current state. Encrypting, decrypting, the plugin protocol, dataless decrypting,
and `-y` recipient conversion work. Hardware testing is currently limited to a YubiKey 5C NFC.

## Install

```bash
cargo install age-plugin-fido2-hmac
```

The installed binary must be on `$PATH` as `age-plugin-fido2-hmac`.

Linux builds need `libudev` headers for `hidapi`.

macOS and Windows need no extra system libraries.

## Usage

Generate an identity and recipient:

```bash
age-plugin-fido2-hmac --generate > identity.txt
```

The output includes a commented recipient line:

```text
# public key: age1fido2-hmac...
AGE-PLUGIN-FIDO2-HMAC-...
```

Encrypt:

```bash
age -r age1fido2-hmac... -o secret.age secret.txt
```

Decrypt with an identity file:

```bash
age -d -i identity.txt secret.age
```

Decrypt without an identity file:

```bash
age -d -j fido2-hmac secret.age
```

Convert an identity file to recipient lines:

```bash
age-plugin-fido2-hmac -y identity.txt > recipients.txt
```

List eligible authenticators and their serials:

```bash
age-plugin-fido2-hmac --list-devices
```

When more than one authenticator is connected, set `FIDO2_SERIAL` to the
serial of the one you want. Same serial format `ykman list` /
`nitropy list` / `solo list` print.

```bash
FIDO2_SERIAL=12345678 age-plugin-fido2-hmac --generate
```

## Compatibility

Supported:

- Recipient lines: `age1fido2-hmac...`
- Plugin stanzas: `fido2-hmac`
- Credential algorithms: `es256` and `eddsa`

## License

`age-plugin-fido2-hmac` is licensed under the MIT license.
