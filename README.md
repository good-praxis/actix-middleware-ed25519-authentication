# Ed25519 Authentication Middleware

A plug-and-play middleware to allow for automatic Ed25519 Authentication for incoming requests on your actix-web server. Simply provide the public key to authenticate the signatures against during registration of the middleware, optionally specify custom header names for the signature and timestamp headers, should they differ from `X-Signature-Ed25519` or `X-Signature-Timestamp` respectively.

## Usage

You can use the Ed25519 Authentication Middleware by wrapping them around your app like this:

### Public Key Only

With a provided Ed25519 `&public_key` of `&str`, you can initalize the middleware thusly:

```
// App::new()
    .wrap(Ed25519Authenticator {
        data: MiddlewareData::new(&public_key),
        })
    })

```

### Public Key and Custom Headers

This previous example assumes the requests you receive to include the headers `X-Signature-Ed25519` and `X-Signature-Timestamp`, should they differ from that default, you can initalize the middleware with custom headers like this:

```
// App::new()
    .wrap(Ed25519Authenticator {
        data: MiddlewareData::new_with_custom_headers(
            &public_key,
            "custom_sig",
            "custom_timestamp",
        ),
    })

```

## Contributing

This crate is passively maintained, should you run into any edge-cases or issues while using this crate, or develop any ideas for useful extension, feel free to start discussions, open issues or open PRs!

## Acknowledgements

The work on this crate would've been impossible without these useful write-ups:

- [Demystifying Actix Web Middleware](https://dev.to/dimfeld/demystifying-actix-web-middleware-3lef) by Daniel Imfeld
- [Validating Discord Slash Command ED25519 Signatures in Rust](https://www.christopherbiscardi.com/validating-discord-slash-command-ed25519-signatures-in-rust) by Chris Biscardi
