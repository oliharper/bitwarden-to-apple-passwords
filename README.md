# Bitwarden to Apple Passwords evidence aid

`bw2apple` prepares a private local case from Bitwarden JSON and Apple Passwords CSV exports. An agent can inspect account metadata, opaque password and note equality labels, ordered text occurrences, match spans, and export limitations without receiving passwords or private note text. The tool does not identify matching accounts, certify a transfer, or read either live vault.

The case retains readable titles, usernames, and website metadata. Keep it private. Password equality is exact; a password found anywhere in Apple does not mean it is present in the relevant entry.

## Build and create a case

Use the Go version pinned in `.mise.toml`:

```sh
go build -o bw2apple ./cmd/bw2apple
./bw2apple compare --bitwarden /path/to/bitwarden.json \
  --apple /path/to/apple.csv --case /path/to/new-private-case
```

The case path must be new and outside this repository. Add `--note /path/to/note.txt` for each optional UTF-8 text file. Use filenames that reveal no secrets.

Ask an agent to review the case using [the agent guide](docs/agent-review.md), without opening the source exports. The default report is compact:

```sh
./bw2apple report --case /path/to/case
./bw2apple report --case /path/to/case --view groups --domain example.co.uk
./bw2apple report --case /path/to/case --view notes
./bw2apple report --case /path/to/case --view limits
```

Groups use the base domain and can be narrowed by exact username. They retain every row and are a lookup aid only. Other views include `records`, `fields`, `absent-passwords`, `matches`, `occurrences`, `coverage`, and `annotations`. Use `--record` with `fields` and `--field` with `matches` or `occurrences`. The [security notes](SECURITY.md) explain the remaining exposure.

To record an explicit user observation separately from computed evidence, create a small JSON file:

```json
{"kind":"related_entry","source_ref":"B0001","destination_ref":"A0002"}
```

```sh
./bw2apple annotate --case /path/to/case --input /path/to/annotation.json
```

Allowed kinds are `reviewed`, `needs_followup`, `related_entry`, `split`, `merge`, and `intentional_difference`. Annotations contain references only; they never alter comparison results.

## Develop

```sh
go test ./...
go vet ./...
mise exec -- golangci-lint run ./...
go build ./...
```

Tests use invented data. SQL bindings are generated with sqlc 1.31.1, pinned in `.mise.toml`: run `mise exec -- sqlc generate` after changing the schema or queries. MIT licensed.
