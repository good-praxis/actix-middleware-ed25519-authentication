use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    error::ErrorUnauthorized,
    http::header::HeaderValue,
    web::Bytes,
    Error,
};
use ed25519_dalek::{PublicKey, Signature, Verifier};
use futures_util::{future::LocalBoxFuture, FutureExt};
use std::{future::Ready, pin::Pin, rc::Rc};

#[derive(Default)]
pub struct AuthenticatorBuilder {
    public_key: Option<String>,
    signature_header: Option<String>,
    timestamp_header: Option<String>,
    reject: bool,
}
impl AuthenticatorBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn public_key(self, public_key: &str) -> Self {
        Self {
            public_key: Some(public_key.into()),
            ..self
        }
    }
    pub fn signature_header(self, header: &str) -> Self {
        Self {
            signature_header: Some(header.into()),
            ..self
        }
    }
    pub fn timestamp_header(self, header: &str) -> Self {
        Self {
            timestamp_header: Some(header.into()),
            ..self
        }
    }
    pub fn reject(self) -> Self {
        Self {
            reject: true,
            ..self
        }
    }
    pub fn build(self) -> Ed25519Authenticator {
        let data: MiddlewareData = self.into();
        data.into()
    }
}

pub struct Ed25519Authenticator {
    pub data: MiddlewareData,
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

impl Default for MiddlewareData {
    fn default() -> Self {
        MiddlewareData {
            public_key: String::new(),
            signature_header: String::from("X-Signature-Ed25519"),
            timestamp_header: String::from("X-Signature-Timestamp"),
            reject: true,
        }
    }
}

impl MiddlewareData {
    pub fn new(public_key: &str) -> Self {
        Self {
            public_key: public_key.into(),
            ..Self::default()
        }
    }
    pub fn new_with_custom_headers(
        public_key: &str,
        signature_header: &str,
        timestamp_header: &str,
    ) -> Self {
        Self {
            public_key: public_key.into(),
            signature_header: signature_header.into(),
            timestamp_header: timestamp_header.into(),
            reject: true,
        }
    }
}

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
            let body = req.extract::<Bytes>().await?;

            let default_header = HeaderValue::from_static("");

            let public_key =
                PublicKey::from_bytes(&hex::decode(&data.public_key).unwrap_or_else(|_| {
                    println!("Couldn't decode public key!");
                    Vec::<u8>::new()
                }))
                .unwrap();

            let timestamp = req
                .headers()
                .get(data.timestamp_header.clone())
                .unwrap_or(&default_header);

            let signature = {
                let header = req
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

            let content = timestamp
                .as_bytes()
                .iter()
                .chain(body.as_ref().iter())
                .cloned()
                .collect::<Vec<u8>>();

            match public_key.verify(&content, &signature) {
                Err(_) => Err(ErrorUnauthorized("Unauthorized")),
                Ok(_) => {
                    let fut = srv.call(req);
                    let res = fut.await?;
                    Ok(res)
                }
            }
        }
        .boxed_local()
    }
}
