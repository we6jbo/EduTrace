# Release checks

1. Verify screenshot MD5 before copying and verify destination again.
2. Review screenshot for private information before any public upload.
3. Build and smoke-test in a temporary private directory; do not touch production data.
4. Check `git status`, `git diff --cached`, and `git ls-files` for secrets before committing.
5. Use a new clean Git repository. Do not publish old `.git` history.
6. Confirm GitHub account, repository name, and public visibility before upload.
7. Snapcraft and Flatpak manifests are drafts; independently validate dependencies and store rules.
