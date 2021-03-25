use crate::Resource;
use include_dir::Dir;
use mime_guess::MimeGuess;
use std::collections::HashMap;

pub fn build_hashmap_from_included_dir(dir: &'static Dir) -> HashMap<&'static str, Resource> {
    let mut map = HashMap::new();

    fn flatten_into(map: &mut HashMap<&'static str, Resource>, dir: &'static Dir) {
        for file in dir.files() {
            map.insert(
                file.path().to_str().expect("Failed to create path"),
                Resource {
                    data: file.contents(),
                    etag: format!("{:x}", md5::compute(file.contents())),
                    mime_type: {
                        let mime = MimeGuess::from_path(file.path()).first_or_octet_stream();
                        format!("{}/{}", mime.type_(), mime.subtype())
                    },
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
