# Keep the evidence private

`compare` reads raw exports and optional note files locally, creates a case, then exits. The case does not store raw passwords, note bodies, or a reverse token dictionary. It does store readable account metadata, opaque equality labels, positions, match spans, search limits, and user annotations; those can still reveal private relationships. It is evidence, not anonymous data.

The tool masks known protected values if they reappear in readable metadata, but it cannot recognize every secret in an account title or filename. Use non-secret names for supplemental files. New cases use `0700` directories and `0600` database files, and existing output paths are refused. Memory zeroization and secure erasure are not guaranteed.

`annotate` uses case references without reopening the exports. `history-export` creates a plaintext password archive with `0600` permissions; keep it away from agents and bug reports. Share invented reproductions, not real exports or cases.
