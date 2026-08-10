# storage

Minimal image server for the EVE PCR prediction demo.

It accepts rootfs image uploads, computes the digest GRUB's `measurefs` extends
into PCR 13, and serves both the metadata and the image itself. The controller
reads the metadata to predict PCR values; the device downloads the image from
the URI in that same metadata.

## Running

```sh
go build -o storage .
./storage -addr :8888 -data ./data
```

Or `make storage` from the demo directory, which builds it to `adam/bin/storage`.

Flags: `-addr` listen address, `-data` where images and metadata are kept,
`-base-url` public base URL for image URIs (defaults to the request host, set it
when devices reach the service under a different name).

## Uploading

```sh
./upload.sh <image-path> [version]
```

The version defaults to the file name without its extension. It must match what
GRUB measures into PCR 8, the string in the `grub_cmd setparams Boot <version>`
event, for example `16.11.0-kvm-amd64`. Override the service address with
`STORAGE_URL`.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/v1/images?name=&version=` | upload, body is the raw image |
| GET | `/api/v1/images` | list all images, newest first |
| GET | `/api/v1/images?version=` | list images for one version, newest first |
| GET | `/api/v1/images/{id}` | metadata for one image |
| GET | `/api/v1/images/{id}/download` | the image bytes |

Looking up a release by version, which is how the controller finds the rootfs
hash for an update it is about to roll out:

```sh
curl -sS 'http://localhost:8888/api/v1/images?version=16.11.0-kvm-amd64'
```

Uploading a changed image under an existing version is allowed, so a version can
match more than one entry. The newest match comes first. An unknown version is
an empty list, not a 404.

Metadata:

```json
{
  "id": "b31985cfca645bd8",
  "name": "rootfs.img",
  "version": "16.11.0-kvm-amd64",
  "sizeBytes": 297500672,
  "sha256": "b31985cf...0a0874a8",
  "rootfsHash": "e19fd58e...f144713f",
  "uri": "http://localhost:8888/api/v1/images/b31985cfca645bd8/download",
  "uploadedAt": "2026-08-03T13:13:22Z"
}
```

## The two digests

They are not interchangeable.

`sha256` covers the whole file. It is what a device checks after downloading.

`rootfsHash` is `evepcr.HashRootfsImage`: SHA-256 over the squashfs payload
only, up to the `total_size` declared in the superblock. This is what GRUB's
`measurefs` extends into PCR 13, and the value PCR prediction needs. For the
same image the two differ, so a whole-file checksum cannot stand in for it.

The image ID is the first 16 hex characters of `sha256`, so re-uploading the
same image updates its entry instead of creating a duplicate.
