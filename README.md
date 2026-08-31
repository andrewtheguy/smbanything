# smbzip

`smbzip` serves one unencrypted ZIP archive as an authenticated, read-only SMB
2.1 share. It is intended for browsing immutable archives without extracting
their directory trees first.

The SMB implementation is adapted from the immutable snapshot service in
`wrustic`. It supports the operations needed to mount, list, stat, and read
files. Write access, create/overwrite dispositions, deletion, and file
execution are rejected by the protocol layer. NTLMv2 authentication and SMB
message signing are required.

## Build and run

```sh
cargo build --release
./target/release/smbzip archive.zip
```

The default listener is IPv4 and IPv6 loopback on port 4456, with share name
`zip` and username `smbzip`. The archive is placed in a directory named with
the first eight hexadecimal characters of the SHA-256 of its absolute path, so
its SMB path is `//127.0.0.1/zip/<8-hex-id>`. A random password is printed for
each run. To use a stable password, pass it through the environment rather than
the process list:

```sh
SMBZIP_PASSWORD='choose-a-strong-password' ./target/release/smbzip archive.zip
```

Useful options:

```text
-p, --port <PORT>    Listen port; 0 chooses an ephemeral port
-s, --share <NAME>   SMB share name (default: zip)
-u, --user <NAME>    SMB username (default: smbzip)
    --bind-all       Listen on every network interface
```

Run `smbzip --help` for the complete command-line help. Set `SMBZIP_LOG=1` for
per-command protocol diagnostics.

## Mounting

The server prints commands containing the actual port, share, and username.
Each command prompts for the password instead of putting it in shell history.

Linux:

```sh
sudo mount -t cifs \
  -o port=4456,vers=2.1,username=smbzip,ro,file_mode=0444,dir_mode=0555 \
  //127.0.0.1/zip/<8-hex-id> /mnt/zip
```

macOS, using Finder → Go → Connect to Server:

```text
smb://smbzip@127.0.0.1:4456/zip/<8-hex-id>
```

Windows 11 24H2 or newer:

```bat
net use Z: \\127.0.0.1\zip\<8-hex-id> * /user:smbzip /TCPPORT:4456
```

Older Windows clients require SMB's standard port 445. On Unix, binding that
privileged port normally requires root or `CAP_NET_BIND_SERVICE`; it can also
conflict with an SMB server already running on the host.

## ZIP behavior

- Only unencrypted entries are accepted. If any entry is encrypted, startup
  fails before the listener is created.
- Stored, Deflate, Deflate64, Bzip2, LZMA, PPMd, XZ, Zstandard, and legacy ZIP
  compression methods supported by the Rust `zip` library are enabled.
- The central directory is indexed at startup. Parent directories omitted from
  the archive are synthesized automatically.
- Unsafe paths, names SMB cannot represent, duplicate paths,
  case-insensitive collisions, and overlapping compressed data are rejected.
- File data is decompressed lazily on first open into an anonymous temporary
  file. This gives efficient positional reads while bounding RAM use. Cached
  data is deleted by the operating system when the process exits.
- The source ZIP is opened read-only and never modified. Do not modify the
  archive in place while it is being served.

## Security boundary

Loopback is the default because SMB 2.1 signing prevents tampering but does not
encrypt file contents. `--bind-all` is an explicit opt-in for remote clients;
anyone able to observe that network traffic can read the transferred data.

Authentication is mandatory—there is no guest path—and every authenticated
message must be signed. The share reports a read-only filesystem with zero free
space, and its backing interface contains no mutation operations. The only SMB
WRITE accepted is a bounded in-memory DCE/RPC request on the `IPC$` `srvsvc`
pipe so clients can enumerate the share; it has no path to archive data.
