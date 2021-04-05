#![doc(test(no_crate_inject))]
/*!
# actix-plus-static-files

## Legal

Dual-licensed under `MIT` or the [UNLICENSE](http://unlicense.org/).

## Overview

- Embed static resources in executable via convenient macro
- Serve static resources as directory in `actix-web`
- Support for angular-like routers
- Fork of actix-web-static-files by Alexander Korolev

## Usage

### Use-case #1: Static resources folder

Create folder with static resources in your project (for example `static`):

```bash
cd project_dir
mkdir static
echo "Hello, world" > static/hello
```

Add to `Cargo.toml` dependency to `actix-web-static-files`:

```toml
[dependencies]
actix-plus-static-files = "0.1.0"
```

Include static files in Actix Web application:

```rust
use actix_web::{App, HttpServer};
use actix_plus_static_files::{build_hashmap_from_included_dir, ResourceFiles, Dir, include_dir};

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

```

Run the server:

```bash
cargo run
```

Request the resource:

```bash
$ curl -v http://localhost:8080/static/hello
*   Trying 127.0.0.1:8080...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 8080 (#0)
> GET /static/hello HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/7.65.3
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< content-length: 13
< date: Tue, 06 Aug 2019 13:36:50 GMT
<
Hello, world
* Connection #0 to host localhost left intact
```

### Use-case #2: Angular-like applications

If you are using Angular (or any of a large variety of other such libraries, such as Svelte + Routify) as frontend, you may want to resolve all not found calls via `index.html` of frontend app. To do this just call method `resolve_not_found_to_root` after resource creation.

```rust
use actix_web::{App, HttpServer};
use actix_plus_static_files::{build_hashmap_from_included_dir, ResourceFiles, Dir, include_dir};

const DIR: Dir = include_dir!("./examples/static");

#[actix_web::main]
async fn main() {
    HttpServer::new(|| {
        let hash_map = build_hashmap_from_included_dir(&DIR);
        App::new().service(ResourceFiles::new("/", hash_map).resolve_not_found_to_root())
    })
        .bind("127.0.0.1:8192")
        .expect("Failed to bind to port")
        .run()
        .await
        .expect("Failed to run server");
}

```

Remember to place you static resources route after all other routes.
*/

mod fs_macro;
mod r#impl;

pub use fs_macro::build_hashmap_from_included_dir;
pub use include_dir::{include_dir, Dir};
pub use r#impl::{
    Resource, ResourceFiles, ResourceFilesInner, ResourceFilesService, UriSegmentError,
};
