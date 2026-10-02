[![Froxlor-CI](https://github.com/Froxlor/Froxlor/actions/workflows/build-mariadb.yml/badge.svg?branch=main)](https://github.com/Froxlor/Froxlor/actions/workflows/build-mariadb.yml)
[![Froxlor-CI](https://github.com/Froxlor/Froxlor/actions/workflows/build-mysql.yml/badge.svg?branch=main)](https://github.com/Froxlor/Froxlor/actions/workflows/build-mysql.yml)
[![Discord](https://badgen.net/badge/icon/discord?icon=discord&label)](https://discord.froxlor.org)

# Froxlor

The server administration software for your needs.
Developed by experienced server administrators, this panel simplifies the effort of managing your hosting platform.

## Installation

### Fast install

1. Ensure that your webserver serves /var/www/html
2. Extract froxlor into /var/www/html
3. Point your browser to http://[ip-of-webserver]/froxlor
4. Follow the installer
5. Login as administrator
6. Have fun!

If you have chosen to do the configuration by hand during the installation, you have to complete some more steps:

1. Adjust "System > Settings" according to your needs
2. Choose your distribution under "System > Configuration"
3. Follow the steps for your services

### Detailed installation

https://docs.froxlor.org/latest/general/installation/

## Help

You may find help in the following places:

### Discord

The froxlor community discord server can be found here: https://discord.froxlor.org

### Forum

The community is located on https://forum.froxlor.org/

### Documentation

The documentation may be found at https://docs.froxlor.org/

## License

May be found in [COPYING](COPYING)

## Downloads

### Tarball

https://files.froxlor.org/releases/froxlor-latest.tar.gz [MD5](https://files.froxlor.org/releases/froxlor-latest.tar.gz.md5) [SHA1](https://files.froxlor.org/releases/froxlor-latest.tar.gz.sha1)

### Debian / Ubuntu repository

[HowTo](https://docs.froxlor.org/latest/general/installation/apt-package.html)

#### Debian

```
apt -y install apt-transport-https lsb-release ca-certificates curl gnupg
curl -sSLo /usr/share/keyrings/deb.froxlor.org-froxlor.gpg https://deb.froxlor.org/froxlor.gpg
sh -c 'echo "deb [signed-by=/usr/share/keyrings/deb.froxlor.org-froxlor.gpg] https://deb.froxlor.org/debian $(lsb_release -sc) main" > /etc/apt/sources.list.d/froxlor.list'
```

#### Ubuntu

```
apt -y install apt-transport-https lsb-release ca-certificates curl gnupg
curl -sSLo /usr/share/keyrings/deb.froxlor.org-froxlor.gpg https://deb.froxlor.org/froxlor.gpg
sh -c 'echo "deb [signed-by=/usr/share/keyrings/deb.froxlor.org-froxlor.gpg] https://deb.froxlor.org/ubuntu $(lsb_release -sc) main" > /etc/apt/sources.list.d/froxlor.list'
```

## Contributing

[see here](.github/CONTRIBUTING.md)
