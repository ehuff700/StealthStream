target=x86_64-unknown-linux-gnum
echo "Building release for target $target"
cargo build --release --target=$target