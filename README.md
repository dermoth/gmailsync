# Gmail Sync Tool

This tool synchronizes Gmail metadata into a MariaDB/InnoDB database to allow
further analysis.

Documentation is yet to be written, most of it is inline in `gmailsync.py` at
the moment.

## Setup

1. Create a virtualenv and add install requirements

   ```sh
   python -mvenv venv
   . venv/bin/activate
   pip install -U pip setuptools
   pip install -r requirements.txt
   ```

2. Create a database

3. Update DB credentials in `gmailsync.py` (TODO: move config to separate file)

4. Follow Google account setup instructions in `gmailsync.py` (in the process
   you should create a file called `gmailsync_client.json`)

4. Run `./gmailsync.py`

## Sample queries

Sample report queries...

### Top 100 senders by count

```sql
SELECT
    COUNT(m.id) AS Count,
    CONCAT(au.user, '@', ad.domain) AS `Sender Email`
FROM messages m
    INNER JOIN messages_labels ml ON m.id = ml.message_id
    INNER JOIN messages_senders ms ON m.id = ms.message_id
    INNER JOIN addresses a ON ms.sender_id = a.id
    INNER JOIN address_users au ON a.id = au.id
    INNER JOIN address_domains ad ON a.id = ad.id
WHERE ml.label_id = 'INBOX'
GROUP BY a.id
ORDER BY Count DESC
LIMIT 100;
```

### Top 100 senders by size

```sql
SELECT
    SUM(m.size)/1024/1024 AS `Size (MB)`,
    COUNT(m.id) AS Count,
    CONCAT(au.user, '@', ad.domain) AS `Sender Email`
FROM messages m
    INNER JOIN messages_labels ml ON m.id = ml.message_id
    INNER JOIN messages_senders ms ON m.id = ms.message_id
    INNER JOIN addresses a ON ms.sender_id = a.id
    INNER JOIN address_users au ON a.id = au.id
    INNER JOIN address_domains ad ON a.id = ad.id
WHERE ml.label_id = 'INBOX'
GROUP BY a.id
ORDER BY `Size (MB)` DESC
LIMIT 100;
```
