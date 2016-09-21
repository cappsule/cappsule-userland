# Cappsule's userland

This repository is part of [Cappsule](https://github.com/cappsule), and contains
the userland part. Please refer to the
[documentation](https://github.com/cappsule/doc/) for more information.



## Architecture

- `api/`: client and server for the JSON API
- `cli/`: `virt` Python script
- `common/`: files shared between the different parts of the project
- `daemon/`: `daemon` which inserts the 2 kernel modules and exposes the API
- `devices/`: `console`, `fs`, `net`, and `gui`
- `include/`: header files
- `logger/`: `logger` binary
- `snapshot/`: `snapshot` binary and cappsules initialization

The [hypervisor repository](https://github.com/cappsule/hypervisor/) is required
to build the project, because it contains header files.
