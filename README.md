# Ed25519 Authentication Middleware

A plug-and-play middleware to allow for automatic Ed25519 Authentication for incoming requests on your actix-web server. Simply provide the public key to authenticate the signatures against during registration of the middleware, optionally specify custom header names for the signature and timestamp headers, should they differ from `X-Signature-Ed25519` or `X-Signature-Timestamp` respectively.

If specified, the middleware will reject any incoming requests that do not validate against the provided public key, or that do not have a valid headers. Otherwise authentication information will be made available as a `AuthenticationInfo` struct in the request extensions.

## Usage

You can use the Ed25519 Authentication Middleware by wrapping them around your app like this:

### Example

With a provided Ed25519 `&public_key` of `&str`, you can initalize the middleware thusly:

```
use actix_middleware_ed25519_authentication::AuthenticatorBuilder;
use actix_web::{web, App, HttpResponse, HttpServer};

HttpServer::new(move || {
         App::new()
            .wrap(
                AuthenticatorBuilder::new()
                .public_key(&public_key) // Required
                .signature_header("X-Signature-Ed25519") // Optional
                .timestamp_header("X-Signature-Timestamp") // Optional
                .reject() // Optional
                .build() // Required
            )
            .route("/", web::post().to(HttpResponse::Ok))
    })
    .bind(("127.0.0.1", 3000))?
    .run()
    .await
```

## Contributing

This crate is passively maintained, should you run into any edge-cases or issues while using this crate, or develop any ideas for useful extension, feel free to start discussions, open issues or open PRs!

## Acknowledgements

The work on this crate would've been impossible without these useful write-ups:

- [Demystifying Actix Web Middleware](https://dev.to/dimfeld/demystifying-actix-web-middleware-3lef) by Daniel Imfeld
- [Validating Discord Slash Command ED25519 Signatures in Rust](https://www.christopherbiscardi.com/validating-discord-slash-command-ed25519-signatures-in-rust) by Chris Biscardi

```

```
