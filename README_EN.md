# iTrustee SDK

## Overview

iTrustee SDK refers to the interfaces, function libraries, and dependencies required by developers to compile Trusted Applications (TAs) based on the secure OS.

## Supported OSs

Architecture: ARM-based servers (for example, Kunpeng 920 servers)

## Build Guide

1. Download the [libboundscheck](https://atomgit.com/openeuler/libboundscheck) library.

2. Extract `libboundscheck` into the `thirdparty/open_source` directory.

3. Build the demo TA via Make:

    ```bash
    cd test/CA/helloworld
    make
    cd test/TA/helloworld
    make
    ```

    Alternatively, build the TA via CMake:

    ```bash
    cd test/TA/helloworld
    bash config.sh
    ```

4. Copy the compiled TA binary (`xxx.sec`) to the `/var/itrustee/ta` directory on the server.

5. Copy the compiled Client Application (CA) binary to the `/vendor/bin` directory on the server. The execution path of the CA may vary with user configurations. Ensure that the CA's actual execution path matches the path configured in the TA.

6. Run the demo CA.

    ```bash
    /vendor/bin/demo_hello
    ```

## Usage

For more details, refer to `iTrustee SDK.chm`.

## Contribution

To contribute code to this repository, please submit a patch or request via email to any of the project maintainers.

If you encounter any bugs or issues, feel free to open an issue.
