# SAML 2.0 Decrypter

A small web-based tool that decrypts SAML 2.0 assertions in the browser using Go WebAssembly.

## Prerequisites

- Go 1.21+ installed
- A working web server to serve static files from the `web/` directory

## Build

From the project root:

- Compile Go to WebAssembly into the `web` directory:

    ```bash
    GOOS=js GOARCH=wasm go build -o ./web/main.wasm ./wasm/wasm_main.go
    ```

- Copy the Go WebAssembly runtime loader into the `web` directory:

    For Go versions 1.24 and later:
    ```bash
    cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" ./web/
    ```

    For Go versions prior to 1.24:
    ```bash
    cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" ./web/
    ```

## Run (using Python simple http server)

Serve the `web` directory with any static file server, for example:

```bash
cd web
python -m http.server 8080
```

Then open:

```text
http://localhost:8080/index.html
```

in a browser that supports WebAssembly and use the UI to decrypt SAML 2.0 assertions.

## Live Demo

[https://puvipavan.github.io/saml-decrypter/](https://puvipavan.github.io/saml-decrypter/)
