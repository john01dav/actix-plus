use actix_plus_static_files::{build_hashmap_from_included_dir, include_dir, Dir, ResourceFiles};
use actix_web::{App, HttpServer};

const DIR: Dir = include_dir!("./examples/static");

#[actix_web::main]
async fn main() {
    HttpServer::new(|| {
        let hash_map = build_hashmap_from_included_dir(&DIR);
        App::new().service(ResourceFiles::new("/", hash_map))
    })
    .bind("127.0.0.1:8192")
    .expect("Failed to bind to port")
    .run()
    .await
    .expect("Failed to run server");
}
