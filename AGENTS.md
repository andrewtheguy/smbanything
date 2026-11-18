strict no backward compatibility or legacy code paths
run cargo clippy and cargo test after rust code changes; a cargo fmt reformat alone runs neither
rust is kept as cargo fmt formats it under rustfmt.toml, and CI checks it
for codex only no cargo fmt because when it does git diff, it gets stuck after cargo fmt
