PODDOS
======

`poddos` is a program that can be used to run Docker / OCI containers. It
supports pulling from Dockerhub-compatible archives and then starting the pulled
layers. It has only a limited set of features. Users looking for a feature-rich
experience are better of using `docker` or `podman`. Users interested in
understanding container-internals may appreciate this code base.

Quick start
-----------
Compile the software using `make`:
```bash
make
sudo make install
```
Compiling requires OpenSSL and zlib headers. Under Ubuntu, those are the
packages `libssl-dev` and `zlib1g-dev`. It installs itself to `/usr/local/bin`
and adds `CAP_NET_ADMIN` to the binary to properly initiatlize networking in
your containers.

Then, pull a container:
```bash
poddos pull --url registry-1.docker.io/library/ubuntu:latest
```
and run it:
```bash
poddos --name ubuntu start
```

Open items
----------
- It looks like containers cannot connect to each other when assigned a macvlan.
- DHCP does not release the IP when `poddos` exits.
- The `FILE` stream helpers cache, which is not needed.
- It cannot be configured whether a pty is generated or not.
- Proper documentation (both code and usage) is lacking.
