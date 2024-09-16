Poddos
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
- DHCP should try release its IP when `poddos` exits.
- The `FILE` stream helpers should not cache.
- A man page should be added.
- Instead of `strncpy`, `strlcpy` (or a safer alternative) should be used.
- There is no tooling to deal with layers, i.e., create and remove layers.
- When pulling, the existing configuration is overwritten.
- There are various statically allocated buffers in use, which should become
  dynamically allocated.
- The http client should simply call `err(...)` when an error occurs.
- The DHCP client does not validate properly the length of its payload, so
  malformed DHCP messages may lead to a buffer overflow.
- The client cannot connect to any of the containers if they use a network
  namespace.
- Working directory is not properly parsed when pulling.
- Read-only bind mounts need to be implemented

Security
--------
Keep in mind that `poddos` does not make any attempt to secure processes in your
container to break out of the namespace. In fact, there are known methods to do
this (e.g., via the /proc/**/exe symlink). This is intentional: the goal of this
software is to run *trusted* containers on a system as first-level clients on a
network. Do not use it to run containers you cannot trust or that have known
security issues.
