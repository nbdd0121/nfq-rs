bindgen \
    --no-doc-comments \
    --use-core \
    --no-prepend-enum-name \
    --blacklist-type '_.+' \
    --ctypes-prefix 'libc' \
    --raw-line '#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals, unused)]use libc::*;type __be16 = u16;type __be32 = u32;type __be64 = u64;' \
    wrapper.h -o binding.rs
rustfmt binding.rs
