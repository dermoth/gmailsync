# Agent guidance

## Test Gmail account

The git-ignored `config.toml` holds the database URL and, in comments, may
have the credentials of a dedicated test Gmail account.

* Access the account only through the app's OAuth API authorization.
* Always confirm with the owner before doing anything else with the account:
  logging in with its password, changing settings, labels or Google Cloud
  configuration, sending, importing or deleting mail.
* Never copy the credentials anywhere else (commits, logs, other files).
