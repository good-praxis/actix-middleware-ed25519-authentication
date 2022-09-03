use std::future::{ready, Ready};

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use futures_util::future::LocalBoxFuture;


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
        println!("Hi from start. You requested: {}", req.path());

        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;

            println!("Hi from response");
            Ok(res)
        })
    }
}

fn main() {
    println!("Development self test:")
}