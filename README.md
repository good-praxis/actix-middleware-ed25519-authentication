# Currently in development towards prototype

# Ed25519 Authentication Middleware
A plug-and-play middleware to allow for automatic Ed25519 Authentication for incoming requests on your actix-web server. Simply provide the public key to authenticate the signatures against during registration of the middleware, optionally specify custom header names for the signature and timestamp headers, should they differ from `X-Signature-Ed25519` or `X-Signature-Timestamp` respectively.