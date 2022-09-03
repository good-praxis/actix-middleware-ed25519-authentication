use std::future::{ready, Ready};

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, error::ErrorUnauthorized,
};
use futures_util::future::LocalBoxFuture;
use ed25519_dalek::{PublicKey, Signature, Verifier};



pub struct Ed25519Authenticator;

impl<S, B> Transform<S, ServiceRequest> for Ed25519Authenticator
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = Ed25519AuthenticatorMiddleware<'static, S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(Ed25519AuthenticatorMiddleware { service, data: MiddlewareData {
            public_key: "foo",
            signature_header_name: "bar",
            timestamp_header_name: "rab",
        } }))
    }
}

pub struct MiddlewareData<'a> {
    public_key: &'a str,
    signature_header_name: &'a str,
    timestamp_header_name: &'a str,
}

pub struct Ed25519AuthenticatorMiddleware<'a, S> {
    service: S,
    data: MiddlewareData<'a>,
}

impl<'a, S, B> Service<ServiceRequest> for Ed25519AuthenticatorMiddleware<'a, S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let public_key = PublicKey::from_bytes(&hex::decode(self.data.public_key).unwrap()).unwrap();
        let timestamp =  req.headers().get(self.data.timestamp_header_name).unwrap();
        let signature = { 
            
            let header = req.headers().get(self.data.signature_header_name).unwrap();
            let decoded_header = hex::decode(header).unwrap();
    
            let mut sig_arr: [u8; 64] = [0; 64];
            for (i, byte) in decoded_header.into_iter().enumerate() {
                sig_arr[i] = byte;
            }
            Signature::from_bytes(&sig_arr).unwrap()
        };
        let content = timestamp.as_bytes().iter().chain(/*FIXME: body.as_bytes()*/"".as_bytes().iter()).cloned().collect::<Vec<u8>>();
    
        match public_key.verify(&content, &signature) {
            Ok(_) =>    { let fut = self.service.call(req);
                Box::pin(async move {
                    let res = fut.await?;
                    Ok(res)
                })},
            Err(_) => Box::pin(ready(Err(ErrorUnauthorized("invalid request signature"))))
        }    
    }
}

fn main() {
    println!("Development self test:")
}