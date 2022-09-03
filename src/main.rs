use std::{future::{ready, Ready}, env, borrow::Borrow};

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, error::ErrorUnauthorized, HttpServer, App, web, HttpResponse,
};
use futures_util::future::LocalBoxFuture;
use ed25519_dalek::{PublicKey, Signature, Verifier};



pub struct Ed25519Authenticator {
    data: MiddlewareData
}


impl<S, B> Transform<S, ServiceRequest> for Ed25519Authenticator
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = Ed25519AuthenticatorMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(Ed25519AuthenticatorMiddleware { service, data: self.data.clone() }))
    }
}

#[derive(Clone, Debug)]
pub struct MiddlewareData {
    public_key: String,
    signature_header_name: String,
    timestamp_header_name: String,
}

pub struct Ed25519AuthenticatorMiddleware<S> {
    service: S,
    data: MiddlewareData,
}

impl<S, B> Service<ServiceRequest> for Ed25519AuthenticatorMiddleware<S>
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
        let data = self.data.clone();

        println!("{:#?}", data);

        let public_key = PublicKey::from_bytes(&hex::decode(&data.public_key).unwrap_or_else(|_| {
            println!("Couldn't decode public key!");
            Vec::<u8>::new()
        })).unwrap();
        let timestamp =  req.headers().get(data.timestamp_header_name).unwrap();
        let signature = { 
            
            let header = req.headers().get(data.signature_header_name).unwrap();
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {

    const PORT: u16 = 3000;
    let public_key = env::var("PUBLIC_KEY").unwrap_or_else(|_| panic!("environment variable \"PUBLIC_KEY\" not found!"));


    HttpServer::new(move || {
        App::new().wrap(Ed25519Authenticator { data: MiddlewareData {public_key: public_key.clone(), signature_header_name: String::from("X-Signature-Ed25519"), timestamp_header_name: String::from("X-Signature-Timestamp") }}).route("/", web::post().to(HttpResponse::Ok))
    })
    .bind(("127.0.0.1", PORT))?
    .run()
    .await
}