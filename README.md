# Femto-Containers

Femto-Containers is a minimal lightweight virtual machine environment for
embedded devices. The virtual machine ISA is adapted from Linux [eBPF].
Femto-Containers is pure C and makes use of some GCC extensions for efficiency.
There is some auxiliary Python tooling to convert compiled Femto-Container
applications into efficient representations.

- [Installation](#installation)
- [Usage](#usage)
- [Development](#development)

# Installation

Femto-Containers is easy to integrate into your existing project. Simply include
all sources from the `src` directory into your compilation infrastructure and
include the `include` directory in your relevant files.

# Usage



# Development

Development of Femto-Containers is still in early stage. Documentation might be
lacking and the API is not yet stabilized. This will get better in the near
future.

[eBPF]: https://ebpf.io/
