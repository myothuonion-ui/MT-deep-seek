# Data and Volume Migration

MT Pentester uses independent runtime names:

- database: `mt_pentester.db`
- log: `mt_pentester.log`
- Docker volume: `mt-pentester-data`
- container user/home: `mt` and `/home/mt`

## Same-directory migration

At container startup, recognized legacy database and log filenames in
`/app/data` are copied to their MT Pentester names only when the new file does
not exist. The old files are preserved. Symlinks and non-regular files are
ignored, new files use mode `0600`, and an existing MT file is never
overwritten. The original `backend.log` default and recognized SQLite
WAL/SHM/journal sidecars are migrated as well. Stop the old deployment cleanly
before migration so its SQLite files are quiescent.

## Named Docker volume migration

First stop the old deployment and make a backup of its data volume. Discover the
exact old volume name with `docker volume ls`; Compose project prefixes vary.
Then run the one-shot, network-disabled migration service:

```bash
export LEGACY_DATA_VOLUME='mt-deep-seek_kmn-data'
export MT_DATA_VOLUME='mt-pentester-data'
docker compose -f compose.migrate.yml run --rm mt-data-migration
```

The service mounts the source read-only, copies top-level regular files without
overwriting destinations, and translates recognized database/log names. It does
not remove the source volume.

Start the new deployment and verify `/health`, session history, report export,
and a fresh backup:

```bash
docker compose -f compose.hardened.yml up --build -d
curl --fail http://127.0.0.1:6000/health
```

Keep the old volume until the new backup has been restored successfully in a
separate test environment. Deleting the source is an explicit operator action;
no MT Pentester migration command performs it.
