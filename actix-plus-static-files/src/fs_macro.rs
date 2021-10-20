use crate::Resource;
use include_dir::Dir;
use mime_guess::MimeGuess;
use std::collections::HashMap;
use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;

/// The Dir type as loaded by the re-exported macro from the include_dir crate provides a recursive data structure with nested directories, but a HashMap of paths to resources is more conducive to serving requests. This function performs the necessary recursion to translate from the former to the latter, and should be called at runtime when initializing Actix web routes.
pub fn build_hashmap_from_included_dir(dir: &'static Dir) -> HashMap<&'static str, Resource> {
    let mut map = HashMap::new();

    fn flatten_into(map: &mut HashMap<&'static str, Resource>, dir: &'static Dir) {
        for file in dir.files() {
            let mime_type = MimeGuess::from_path(file.path()).first_or_octet_stream();

            let data_gzip = (!mime_type.essence_str().starts_with("image/")).then(|| {
                let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
                encoder.write_all(file.contents()).unwrap();
                encoder.finish().unwrap()
            });


            map.insert(
                file.path().to_str().expect("Failed to create path"),
                Resource {
                    data: file.contents(),
                    data_gzip,
                    etag: format!("{:x}", md5::compute(file.contents())),
                    mime_type,
                },
            );
        }
        for subdir in dir.dirs() {
            flatten_into(map, subdir);
        }
    }
    flatten_into(&mut map, dir);

    map
}
