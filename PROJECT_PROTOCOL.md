# Project Protocol for Secret Sentinel

## Core ownership and identity rules

1. This project belongs to the repository owner and is not to be treated as a shared public identity project.
2. The normal Git commit flow is allowed to use the owner’s current Git identity, including the owner’s current name and email, for local commit metadata.
3. Public-facing project metadata must not expose the owner’s personal email address.
4. If an email is needed in public metadata, use a neutral dummy or project email such as:
   - hello@secretsentinel.example
   - support@secretsentinel.example
5. Public files must never include the owner’s personal email or personal username in metadata, docs, or config unless explicitly requested.
6. The owner’s personal Git identity belongs in local Git config and commit metadata, not in public project files.
7. The repo’s public metadata and the local Git identity are separate things. One is for GitHub/public history; the other is for local commit attribution.
8. If GitHub blocks a push because the email is private, the fix is to either:
   - make the email public in GitHub settings, or
   - use the GitHub noreply address for commit identity while keeping public project files neutral.
9. The normal commit flow is still valid; the public repo metadata and GitHub email privacy rules are separate concerns.

## Secret and environment safety rules

1. No environment variables, API keys, tokens, credentials, secrets, or private infrastructure details may be committed to the repository.
2. No public-facing README, config, or code should mention real secrets, private endpoints, internal infrastructure, cloud keys, or local credential paths.
3. If any secret-like value is found in tracked files or git history, it must be removed and rewritten from history when necessary.
4. Default behavior must be safe-by-default and require no env var setup for normal usage.
5. Any optional AI or cloud features must be explicitly described as optional and not required for the project to work.

## Privacy and internal workflow rules

1. Chat logs, tool commands, local testing output, or internal debugging notes are not to be published in repo files.
2. Do not add commentary or documentation that records internal commands, AI actions, or testing history into project-facing files.
3. Git-tracked files should remain collaborator-facing and concise. Avoid internal operational notes.
4. No “we ran tests”, “I did X”, or operational logs should be inserted into the codebase or README unless directly requested by the owner.

## Documentation rules

1. README content must be focused on collaborator-facing usage, installation, and project purpose.
2. README files must not contain private notes, infra details, API secrets, or internal workflow logs.
3. Public docs must be minimal, clear, and professional.
4. Documentation should describe how to use the tool, not explain private development history or commands

## Execution and approval rules

1. Before making any code or repo changes, explain the intended action to the user and wait for approval.
2. Do not run build, install, test, or commit commands until the user approves the change.
3. Never create a commit or merge without explicit approval from the user.
4. Local testing should happen first, and the user should explicitly approve before any commit or merge is made.
5. If a command is likely to change files, the user must approve it before executing.
6. Files or folders which are not needed for this application/project to work must not be committed and kept in gitignore.
7. If a push is blocked by GitHub email privacy restrictions, the user must approve whether to:
   - make the email public, or
   - use a GitHub noreply email for the public-safe commit identity.

## Repository hygiene rules

1. Ignore internal session history, local environment files, logs, and any non-source files that should not be public.
2. Keep only project-relevant files in version control.
3. Use neutral project metadata in all public-facing files.
4. Keep the repository clean and free from accidental secrets or developer-only notes.

## Required behavior for future tasks

Before starting any task, read this protocol file first. If a request conflicts with these rules, stop and ask for confirmation instead of proceeding.


## Once all protocols are followed and abided, you report to me with a message that everything is working and all the protocols are followed. If all protocols are followed, you request me to commit but in that report you must mention that everything is working as per the flow.