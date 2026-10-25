# EduTrace 0.7.0 — local research session

This source package is designed to be public-safe. It contains **no personal school history, family research notes, addresses, passphrases, or encryption keys**. Private research records and identifying provenance information must not be included in public releases.

## Commands

- `EduTrace` or `EduTrace research`: interactive local command session (requires terminal)
- `EduTrace init`: initialize private local storage
- `EduTrace add-note`: append encrypted text, ending with `.END` on its own line
- `EduTrace read-notes`: print decrypted notes to the local terminal
- `EduTrace status`: show status without disclosing note contents
- `EduTrace verify-challenge`: verify existing local HMAC challenge
- `EduTrace help`: command summary

The local key is generated randomly at `/var/lib/edutrace-private/local.key`, mode 0600. Back it up securely alongside the encrypted files; losing the key makes them unrecoverable. Anyone running as the same Linux account may decrypt files. This is protection against casual file exposure, not a security boundary against compromise of your Linux account.

**No network connections, remote commands, AI integrations, automatic plugin execution, Moltbook posts, IRC connections, or exports are implemented.** A phrase such as `run edutrace` is a convenience activation instruction for an AI assistant with terminal access, not a password. Future outbound integrations should preview and explicitly approve each payload, with sensitive information removed by default.

The legacy Qt Creator filenames are kept even though the program is a CLI, not a GUI. Old `ET01` passphrase files cannot be decrypted by this version; preserve the previous binary and original passphrase if you need to migrate them. The `ET02` local-key format is retained from 0.3.0.

## Local research commands

- `EduTrace search 'some phrase'` finds case-insensitive lines in encrypted notes.
- `EduTrace ask 'What is known about a subject?'` finds lines containing meaningful question terms. It **does not generate answers** or establish historical facts.
- `EduTrace add-source` prompts for a source title, reference and description and encrypts them locally.
- `EduTrace sources` lists local source references. In interactive mode, use `search TEXT`, `ask QUESTION`, `add-source`, and `sources`.
- No automatic network access, AI model calls, IRC, or Moltbook publication.
- Research content and encryption keys must remain outside source control. The current installation uses `/var/lib/edutrace-private/`.
- Keep your `local.key` securely backed up **separately** from public source. Losing it makes ET02 files unrecoverable.

## Private storage migration

The installer creates `/var/lib/edutrace-private` (0700, owned by the installing user), and **copies** the existing private encrypted files and local key from `~/.edutrace-private` without decrypting them. It leaves the original directory intact as a recovery copy. It refuses a migration if the destination is not empty, or the legacy directory contains symlinks or non-regular files. It verifies each copied file by SHA-256 and requires private file permissions. A missing legacy directory initializes empty storage.

**Do not delete the old directory** until you have verified your notes and have a secure backup of the encryption key. The installer does not touch downloaded plaintext research snapshots; any previously downloaded plaintext file still needs separate handling. No personal research is bundled. This path is local machine storage, not a new security boundary against the same Linux account.
