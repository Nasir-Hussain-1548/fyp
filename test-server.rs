use std::net::SocketAddr;
use tokio::net::TcpListener;
use axum::{Router, response::Html};

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("Binding to {}", addr);
    
    let listener = TcpListener::bind(addr)
        .await
        .expect("Failed to bind");
    
    println!("Successfully bound!");
    
    let app = Router::new()
        .fallback(|| async { Html("Hello!") });
    
    println!("Starting serve...");
    axum::serve(listener, app)
        .await
        .expect("Server error");
}
