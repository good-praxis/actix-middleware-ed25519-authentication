use actix_middleware_ed25519_authentication::AuthenticatorBuilder;
use actix_web::{web, App, HttpResponse, HttpServer};
use std::env;

// For testing during development
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    const PORT: u16 = 3000;
    let public_key = env::var("PUBLIC_KEY")
        .unwrap_or_else(|_| panic!("environment variable \"PUBLIC_KEY\" not found!"));

    HttpServer::new(move || {
        App::new()
            .wrap(
                AuthenticatorBuilder::new()
                    .public_key(&public_key)
                    .reject()
                    .build(),
            )
            .route("/", web::post().to(HttpResponse::Ok))
    })
    .bind(("127.0.0.1", PORT))?
    .run()
    .await
}
