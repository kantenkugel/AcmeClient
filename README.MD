# AcmeClient

This project uses [acme4j](https://github.com/shred/acme4j) and parts of its example code 
to create a simple command-line client for creating/renewing letsencrypt certificates.

It uses local server directories and the `http-01` challenge type to accomplish that.

## Usage

This program has 2 execution modes: `register` and `renew`

### Register

Used to create a new certificate. 
By default this will create/use the key file located in `site.key` and store the certificate as `site.crt`.
Can be overridden via options.

Usage:
```sh
java -jar AcmeClient.jar register [options] -w /webroot/for/domain -d first.domain.com -d ...
```

Available options:
- `--override`

  Used to signal that all previously registered domains (stored in a config file) are to be ignored and discarded.
  This will remove them from the config file and only add newly defined ones.
  Therefore, this might break renewal of old domains.

- `-q`, `--quiet`

  Do not ask for confirmation of data and accept CA ToS automatically. Not recommended.

- `-k KEYFILE`, `--key KEYFILE`

  Tells AcmeClient to use a different key-file location instead.

- `-c CERTFILE`, `--cert CERTFILE`

  Tells AcmeClient to use a different file location to store the generated certificate in.

`-w` or `--webroot` is used to define a webroot for following domain declarations. It can be used multiple times like
`-w /first -d first.domain.com -w /second -d second.domain.com` to be able to have different webroots per domain.

`-d` or `--domain` is used to define what domains to register. It uses the most recent webroot defined via `-w` as its webroot.

### Renew

Used to renew previously registered certificate.

Usage:
```sh
java -jar AcmeClient.jar renew
```

This will use the config file generated from a previous `register` command to renew all the registered domains with exactly the same configuration.

Will exit with status code `2`, if certificate is still valid for more than `10` days. Otherwise it will renew and exit with code `0`.

## Building from Source

To build AcmeClient yourself, all you need to do is cloning the repo and (provided you have a proper JDK installed) 
run the command `./gradlew shadowJar`. This will generate the executable in the `build/libs` directory.