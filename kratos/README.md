# Ory Kratos

## Install

1. Head over to <https://github.com/ory/kratos/releases/tag/v0.11.1>
2. Download the binary you require

```bash
kratos_url=https://github.com/ory/kratos/releases/download/v0.11.1/kratos_0.11.1-linux_sqlite_libmusl_64bit.tar.gz

cd `mktemp -d`

wget $kratos_url
tar xf 'kratos_0.11.1-linux_sqlite_libmusl_64bit.tar.gz'

sudo install kratos /usr/local/bin

# verify
kratos version

# bash completion available: bash, fish, powershell, zsh
kratos completion bash | sudo tee /etc/bash_completion.d/kratos
```
