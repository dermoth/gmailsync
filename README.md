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
