//! Actix-web middleware for ed25519 signature validation of incoming requests.
//!
//! Provides a middleware that can be used to validate the signature of
//! incoming requests. Offering these features:
//! - Signature validation via public key
//! - Customizable header names for signature and timestamp
//! - Authentication status is available in the request extensions.
//! - Optional automatic rejection of invalid requests
//!
//! # Example
//!
//! ```rust
//! use actix_middleware_ed25519_authentication::AuthenticatorBuilder;
//! use actix_web::{web, App, HttpResponse, HttpServer};
//!
//! HttpServer::new(move || {
//!         App::new()
//!             .wrap(
//!                 AuthenticatorBuilder::new()
//!                 .public_key(&public_key)
//!                 .signature_header("X-Signature-Ed25519")
//!                 .timestamp_header("X-Signature-Timestamp")
//!                 .reject()
//!                 .build()
//!             )    
//!             .route("/", web::post().to(HttpResponse::Ok))
//!  })
//! .bind(("127.0.0.1", 3000))?
//! .run()
//! .await
//!```  
//!
use actix_http::{h1::Payload, Request};
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    error::ErrorUnauthorized,
    http::header::HeaderValue,
    web::BytesMut,
    Error, HttpMessage, HttpRequest,
};
use ed25519_dalek::{PublicKey, Signature, SignatureError, Verifier};
use futures_util::{future::LocalBoxFuture, FutureExt, StreamExt};
use std::{
    future::{ready, Ready},
    pin::Pin,
    rc::Rc,
};

#[derive(Default)]
/// `AuthenticatorBuilder` is a [builder](https://rust-unofficial.github.io/patterns/patterns/creational/builder.html) struct that holds the public key, signature header, timestamp header,
/// and a boolean value that indicates whether or not to reject requests.
///
/// Properties:
///
/// * `public_key`: The public key that will be used to verify the signature.
/// **For a successful build of the authenticator, a public key will be required**.
/// * `signature_header`: The name of the header that contains the signature.
/// * `timestamp_header`: The name of the header that contains the timestamp.
/// * `reject`: If true, the middleware will reject the request if it is not signed.
///  If false, the middleware will allow the request to continue, adding [`AuthenticationInfo`] to the request extensions.
pub struct AuthenticatorBuilder {
    public_key: Option<String>,
    signature_header: Option<String>,
    timestamp_header: Option<String>,
    reject: bool,
}
impl AuthenticatorBuilder {
    /// Creates a new `AuthenticatorBuilder` with default values.
    /// **Without a public key, the builder will panic on build.**
    pub fn new() -> Self {
        Self::default()
    }
    /// Sets the public key that will be used to verify the signature.
    /// **Required.**
    ///
    /// # Arguments
    /// * `public_key`: The public key that will be used to verify the signature. Must be a valid ed25519 public key for successful validation. Must be a hex-encoded string.
    pub fn public_key(self, public_key: &str) -> Self {
        Self {
            public_key: Some(public_key.into()),
            ..self
        }
    }
    /// Sets the name of the header that contains the signature.
    /// If not set, the default value is `X-Signature-Ed25519`.
    /// *optional*
    ///
    /// # Arguments
    /// * `header`: The name of the header that contains the signature.
    pub fn signature_header(self, header: &str) -> Self {
        Self {
            signature_header: Some(header.into()),
            ..self
        }
    }
    /// Sets the name of the header that contains the timestamp.
    /// If not set, the default value is `X-Signature-Timestamp`.
    /// *optional*
    ///
    /// # Arguments
    /// * `header`: The name of the header that contains the timestamp.
    pub fn timestamp_header(self, header: &str) -> Self {
        Self {
            timestamp_header: Some(header.into()),
            ..self
        }
    }
    /// Sets whether or not to reject requests that are not signed.
    /// If not set, the default value is `false`.
    /// *optional*
    pub fn reject(self) -> Self {
        Self {
            reject: true,
            ..self
        }
    }
    /// Converts the builder into the service factory [`Ed25519Authenticator`], as expected
    /// by actix-web's [`wrap`](actix_web::App::wrap) function.
    /// # Panics
    /// If the builder is missing a public key, this function will panic.
    ///
    /// If the public key is not a valid ed25519 public key provided as a hex string, this function will panic.
    pub fn build(self) -> Ed25519Authenticator {
        let data: MiddlewareData = self.into();
        data.into()
    }
}

/// Ed25519Authenticator is a middleware factory that generates [`Ed25519AuthenticatorMiddleware`],
/// which verifies the signature of incoming request.
/// It is created through the [`AuthenticatorBuilder`] and consumed by actix-web's [`wrap`](actix_web::App::wrap) function.
///
/// It is a [transform](https://docs.rs/actix-web/4.1.0/actix_web/dev/trait.Transform.html) service factory.
pub struct Ed25519Authenticator {
    data: MiddlewareData,
}

impl<S, B> Transform<S, ServiceRequest> for Ed25519Authenticator
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = Ed25519AuthenticatorMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        std::future::ready(Ok(Ed25519AuthenticatorMiddleware {
            service: Rc::new(service),
            data: Rc::new(self.data.clone()),
        }))
    }
}

impl From<MiddlewareData> for Ed25519Authenticator {
    fn from(data: MiddlewareData) -> Self {
        Self { data }
    }
}

/// MiddlewareData is a struct that holds the public key, signature header name, timestamp header name, and a boolean value that indicates whether or not to reject requests.
/// When used with the [`authenticate_request`](fn.authenticate_request.html) function, the rejection boolean is ignored.
#[derive(Clone, Debug)]
pub struct MiddlewareData {
    public_key: String,
    signature_header: String,
    timestamp_header: String,
    reject: bool,
}

impl From<AuthenticatorBuilder> for MiddlewareData {
    fn from(builder: AuthenticatorBuilder) -> Self {
        Self {
            public_key: builder.public_key.unwrap(),
            signature_header: builder
                .signature_header
                .unwrap_or_else(|| "X-Signature-Ed25519".into()),
            timestamp_header: builder
                .timestamp_header
                .unwrap_or_else(|| "X-Signature-Timestamp".into()),
            reject: builder.reject,
        }
    }
}

impl MiddlewareData {
    /// Creates a new `MiddlewareData` with default headers. Intended to be used with the [`authenticate_request`](fn.authenticate_request.html) function.
    pub fn new(public_key: &str) -> Self {
        Self {
            public_key: public_key.into(),
            signature_header: "X-Signature-Ed25519".into(),
            timestamp_header: "X-Signature-Timestamp".into(),
            reject: false,
        }
    }
}

/// AuthenticationInfo is a struct that holds information about the authentication of a request. This struct is added to the request extensions.
#[derive(Debug)]
pub struct AuthenticationInfo {
    pub authenticated: bool,
}

/// Ed25519AuthenticatorMiddleware is a middleware that verifies the signature of incoming request.
/// It is generated by the [`Ed25519Authenticator`] middleware factory and not intended to be used directly.
///
/// It is a [service](https://docs.rs/actix-web/4.1.0/actix_web/dev/trait.Service.html) middleware.
pub struct Ed25519AuthenticatorMiddleware<S> {
    service: Rc<S>,
    data: Rc<MiddlewareData>,
}

impl<S, B> Service<ServiceRequest> for Ed25519AuthenticatorMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    /// # Panics
    /// If reject is set to false, and the signature is invalid, this function will panic. This is unimplemented behavior.
    fn call(
        &self,
        mut req: ServiceRequest,
    ) -> Pin<
        Box<
            (dyn futures_util::Future<Output = Result<ServiceResponse<B>, actix_web::Error>>
                 + 'static),
        >,
    > {
        let data = self.data.clone();
        let srv = self.service.clone();

        async move {
            let verify = authenticate_request(&mut req, &data).await;

            match (verify, data.reject) {
                (Err(_), true) => Err(ErrorUnauthorized("Unauthorized")),
                (Err(_), false) => {
                    req.extensions_mut().insert(AuthenticationInfo {
                        authenticated: false,
                    });
                    let fut = srv.call(req);
                    let res = fut.await?;
                    Ok(res)
                }
                (Ok(new_req), _) => {
                    new_req.extensions_mut().insert(AuthenticationInfo {
                        authenticated: true,
                    });
                    let fut = srv.call(new_req); // FIXME: Panics
                    let res = fut.await?;
                    Ok(res)
                }
            }
        }
        .boxed_local()
    }
}

/// authenticate_request is a function that verifies the signature of an incoming request.
/// Intended to allow for manual handling of authentication, or for use with other middleware.
///
/// # Arguments
/// * `req` - mutable reference to the incoming request
/// * `data` - reference to the [`MiddlewareData`] struct
///
/// Note: This function does not add the [`AuthenticationInfo`] struct to the request extensions.
/// Additionally, this function does not reject requests if the signature is invalid.
/// Instead, it returns a [`Result`] with an [`Error`] if the signature is invalid.
pub async fn authenticate_request(
    req: &mut ServiceRequest,
    data: &MiddlewareData,
) -> Result<ServiceRequest, SignatureError> {
    let (http_request, body) = req.parts_mut();

    let default_header = HeaderValue::from_static("");

    let public_key = PublicKey::from_bytes(&hex::decode(&data.public_key).unwrap_or_else(|_| {
        println!("Couldn't decode public key!");
        Vec::<u8>::new()
    }))
    .unwrap();

    let timestamp = http_request
        .headers()
        .get(data.timestamp_header.clone())
        .unwrap_or(&default_header);

    let signature = {
        let header = http_request
            .headers()
            .get(data.signature_header.clone())
            .unwrap_or(&default_header);
        let decoded_header = hex::decode(header).unwrap();

        let mut sig_arr: [u8; 64] = [0; 64];
        for (i, byte) in decoded_header.into_iter().enumerate() {
            sig_arr[i] = byte;
        }
        Signature::from_bytes(&sig_arr).unwrap()
    };

    let mut payload = BytesMut::new();

    while let Some(item) = body.next().await {
        if let Ok(b) = item {
            payload.extend_from_slice(&b)
        }
    }

    let content = timestamp
        .as_bytes()
        .iter()
        .chain(&payload)
        .cloned()
        .collect::<Vec<u8>>();

    let mut new_payload = Payload::create(true);
    new_payload.1.unread_data(payload.into());

    match public_key.verify(&content, &signature) {
        Err(e) => Err(e),
        Ok(()) => Ok(ServiceRequest::from_parts(
            http_request.to_owned(),
            new_payload.1.into(),
        )),
    }
}
