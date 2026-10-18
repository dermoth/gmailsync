#!/usr/bin/env python3
#
# Synchronizes gmail account to MariaDB
#
# Copyright (C) 2024 Thommas Guyot-Sionnest <tguyot@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""gmailsync"""

import sys
import os
import time
import getpass
import json
import random
import tomllib
from pathlib import Path
from email.utils import getaddresses
from http.client import HTTPException
from collections import Counter, deque
from collections.abc import Iterable, Iterator, Mapping
from typing import Literal, Optional
#from typing import List, Optional

from google.auth.exceptions import TransportError
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import BatchError, HttpError
from httplib2 import HttpLib2Error

from sqlalchemy import Boolean, Enum, ForeignKey
from sqlalchemy import create_engine, select, insert, delete
#from sqlalchemy import UniqueConstraint, MetaData
#from sqlalchemy import create_mock_engine
from sqlalchemy.dialects.mysql import VARCHAR, TEXT, INTEGER, BIGINT
from sqlalchemy.orm import DeclarativeBase, mapped_column
from sqlalchemy.orm import Mapped, Session
from sqlalchemy.orm import relationship

# pylint: disable=too-few-public-methods
class Base(DeclarativeBase):
    """Base class for all ORM tables"""
    __table_args__ = ({"mysql_engine": "InnoDB"},)

class Addresses(Base):
    "Email Addresses Sequence"
    __tablename__ = 'addresses'

    id: Mapped[int] = mapped_column(primary_key=True)

class AddressUsers(Base):
    "Email Usernames table"
    __tablename__ = 'address_users'

    id: Mapped[int] = mapped_column(ForeignKey('addresses.id'), primary_key=True)
    # Considering the MAIL FROM/RCPT TO 255 length limit
    user: Mapped[str] = mapped_column(VARCHAR(253), index=True)
    address: Mapped["Addresses"] = relationship()

class AddressDomains(Base):
    "Email Domains table"
    __tablename__ = 'address_domains'

    id: Mapped[int] = mapped_column(ForeignKey('addresses.id'), primary_key=True)
    # Considering the MAIL FROM/RCPT TO 255 length limit
    domain: Mapped[str] = mapped_column(VARCHAR(253), index=True)
    address: Mapped["Addresses"] = relationship()

class AddressNames(Base):
    "Email Names table"
    __tablename__ = 'address_names'

    id: Mapped[int] = mapped_column(ForeignKey('addresses.id'), primary_key=True)
    name: Mapped[str] = mapped_column(VARCHAR(16191), index=True)
    address: Mapped["Addresses"] = relationship()

class Labels(Base):
    """Labels table"""
    __tablename__ = 'labels'

    id: Mapped[str] = mapped_column(
        VARCHAR(254, charset='ascii'),
        primary_key=True,
    )
    name: Mapped[str] = mapped_column(VARCHAR(84), index=True)
    type: Mapped[Literal['system', 'user']] = mapped_column(
        Enum('system', 'user'),
        index=True,
    )

class Messages(Base):
    """Messages Table"""
    __tablename__ = 'messages'

    id: Mapped[str] = mapped_column(
        VARCHAR(254, charset='ascii'),
        primary_key=True,
    )
    threadId: Mapped[str] = mapped_column(VARCHAR(254, charset='ascii'), index=True)
    snippet: Mapped[str] = mapped_column(TEXT())
    size: Mapped[int] = mapped_column(INTEGER(unsigned=True), index=True)
    recv: Mapped[int] = mapped_column(BIGINT(unsigned=True), index=True)

class MessagesSenders(Base):
    """Message Senders relation"""
    __tablename__ = 'messages_senders'

    message_id: Mapped[str] = mapped_column(ForeignKey('messages.id'), primary_key=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey('addresses.id'), primary_key=True)
    # Per the RFC if there is more than one From addr there MUST be one Sender
    type: Mapped[Literal['from', 'sender', 'none']] = mapped_column(
        Enum('from', 'sender', 'none'),
        primary_key=True,
    )
    primary: Mapped[bool] = mapped_column(Boolean)

class MessagesReceivers(Base):
    """Message Recipients relation"""
    __tablename__ = 'messages_receivers'

    message_id: Mapped[str] = mapped_column(ForeignKey('messages.id'), primary_key=True)
    receiver_id: Mapped[int] = mapped_column(ForeignKey('addresses.id'), primary_key=True)
    type: Mapped[Literal['to', 'cc']] = mapped_column(
        Enum('to', 'cc'),
        primary_key=True,
    )

class MessagesLabels(Base):
    """Message Labels relation"""
    __tablename__ = 'messages_labels'

    message_id: Mapped[str] = mapped_column(ForeignKey('messages.id'), primary_key=True)
    label_id: Mapped[str] = mapped_column(ForeignKey('labels.id'), primary_key=True)
# pylint: enable=too-few-public-methods

# Gmail API cost in quota units, see:
# https://developers.google.com/workspace/gmail/api/reference/quota
COST_GET = 20
COST_LIST = 5
COST_LABELS = 1

# Transient network failures, including token refreshes (TransportError)
NETWORK_ERRORS = (OSError, HTTPException, HttpLib2Error, TransportError)

def is_rate_limit(err: HttpError) -> bool:
    """Return whether err is a Gmail rate limit error (429, or 403 with a rate limit reason)"""
    content = err.content.decode(errors='replace') if isinstance(err.content, bytes) else str(err.content)
    return err.resp.status == 429 or (err.resp.status == 403 and 'ratelimitexceeded' in content.lower())

class Throttle:
    """Paces quota usage and backs off after errors"""
    MAX_BACKOFF = 64

    def __init__(self, units_per_min: int, burst: int):
        self.rate = units_per_min / 60
        self.burst = burst
        self.next = time.monotonic()
        self.failures = 0

    def spend(self, units: int):
        """Wait until units can be spent without exceeding the rate (allowing a burst)"""
        now = time.monotonic()
        self.next = max(self.next, now) + units / self.rate
        wait = self.next - now - self.burst / self.rate
        if wait > 0:
            time.sleep(wait)

    def backoff(self, reason: str, retry_after: Optional[str] = None):
        """Truncated exponential backoff with jitter, honoring Retry-After"""
        delay = min(2 ** self.failures, self.MAX_BACKOFF) + random.random()
        if retry_after and retry_after.isdigit():
            delay = max(delay, int(retry_after))
        self.failures = min(self.failures + 1, 10)
        print(f'{reason}, retrying in {delay:.1f}s')
        time.sleep(delay)

    def success(self):
        """Reset the backoff after a successful request"""
        self.failures = 0

class GmailClient:
    """Gmail Client"""
    SCRIPT = Path(__file__)
    CLIENT = SCRIPT.with_name('gmailsync_client.json')
    # If modifying these scopes, delete the file token.json.
    SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
    # Stay below the 6000 units per user per minute quota; Google recommends
    # batches of no more than 50 requests.
    QUOTA_PER_MIN = 5000
    BATCH_SIZE = 50
    # Attempts for messages failing on their own (not rate limits or whole batch errors)
    MAX_ATTEMPTS = 8

    def __init__(self, userid: str = 'me'):
        if not self.CLIENT.exists():
            print(
                'Please create and download an OAuth 2.0 Client for'
                ' Gmail API from Google Cloud Console:',
                '  -> https://console.cloud.google.com/apis/credentials',
                f'The file should be named `{self.CLIENT.name}\' in the same'
                ' directory as this script.',
                sep='\n',
            )
            sys.exit(1)

        with self.CLIENT.open('r', encoding='utf8') as fhd:
            stat = os.fstat(fhd.fileno())
            if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
                print(f'ERROR: Unsafe file permissions for {self.CLIENT}.',
                      file=sys.stderr)
                sys.exit(1)
            client = json.load(fhd)

        print("""
        Authenticating to Gmail...

        1. Click on the link and get the authorization code from the OAuth page

        2. Enter the authorization code in the prompt below
        """)

        #os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
        flow = InstalledAppFlow.from_client_config(client, self.SCOPES)
        #creds = flow.run_console()
        #session = flow.authorized_session()
        flow.redirect_uri = 'urn:ietf:wg:oauth:2.0:oob'
        authurl, _ = flow.authorization_url()
        #display(Javascript(f'window.open("{authurl}");'))
        print(authurl)
        authcode = getpass.getpass('Authorization code: ')
        flow.fetch_token(code=authcode)
        self.service = build('gmail', 'v1', credentials=flow.credentials)
        self.userid = userid

        self.throttle = Throttle(self.QUOTA_PER_MIN, self.BATCH_SIZE * COST_GET)

    def _execute(self, req, units: int):
        """Execute a request (or a whole batch), retrying transient errors forever"""
        while True:
            self.throttle.spend(units)
            try:
                return req.execute()
            except BatchError as err:  # Malformed batch response, subclass of HttpError
                self.throttle.backoff(f'Batch error ({err})')
            except HttpError as err:
                if not is_rate_limit(err) and err.resp.status < 500:
                    raise
                self.throttle.backoff(f'HTTP error {err.resp.status}', err.resp.get('retry-after'))
            except NETWORK_ERRORS as err:
                self.throttle.backoff(f'Network error ({err!r})')

    def _list_msgids(self) -> list[str]:
        """Return the ids of all messages in the mailbox (excluding spam and trash)"""
        messages = self.service.users().messages()  # pylint: disable=no-member
        msgids = {}  # Used as an ordered set
        req = messages.list(userId=self.userid, maxResults=500)
        while req:
            resp = self._execute(req, COST_LIST)
            msgids.update((msg['id'], None) for msg in resp.get('messages', []))
            req = messages.list_next(req, resp)
        return list(msgids)

    def get_labels(self) -> list[dict[str, str]]:
        """Return all labels for the mailbox
        """
        # pylint: disable=no-member
        res = self._execute(self.service.users().labels().list(userId=self.userid), COST_LABELS)
        return res.get('labels', [])

    def _get_batch(self, msgids: list[str], headers: list[str]) -> dict[str, tuple]:
        """Get msgids metadata in a single batch request, return {msgid: (message, error)}"""
        messages = self.service.users().messages()  # pylint: disable=no-member
        results = {}
        batch = self.service.new_batch_http_request(  # pylint: disable=no-member
            callback=lambda req_id, resp, err: results.__setitem__(req_id, (resp, err)),
        )
        for msgid in msgids:
            batch.add(
                messages.get(userId=self.userid, id=msgid, format='metadata', metadataHeaders=headers),
                request_id=msgid,
            )
        self._execute(batch, COST_GET * len(msgids))
        return results

    def proc_msg_batch(self, cb_proc, headers, skip: set):  # pylint: disable=too-many-locals,too-many-branches
        """Fetch all messages not in skip and pass them to cb_proc in batches
        Listed msgid's are removed from skip, leaving only those gone from the mailbox.

        Rate limits and failures of a whole batch (network errors...) back off
        and are retried forever without counting against messages. Other
        transient errors on a single message are retried MAX_ATTEMPTS times.
        """
        print('*** Listing messages...')
        queue = deque()
        for msgid in self._list_msgids():
            if msgid in skip:
                skip.remove(msgid)
            else:
                queue.append(msgid)

        total = len(queue)
        print(f'*** Fetching {total} new messages...')
        attempts = Counter()
        done = failed = 0
        start = lastprint = time.monotonic()
        while queue:
            ids = [queue.popleft() for _ in range(min(self.BATCH_SIZE, len(queue)))]
            results = self._get_batch(ids, headers)
            msgs = []
            retry_err = None
            for msgid in ids:
                resp, err = results.get(msgid, (None, None))
                if resp:
                    msgs.append(resp)
                elif err and is_rate_limit(err):
                    queue.append(msgid)
                    retry_err = err
                elif err and err.resp.status == 401:
                    raise err
                elif err and err.resp.status < 500:
                    # Not retryable, ex. 404 if the message was deleted since listing
                    print(f'Skipping message {msgid}: HTTP error {err.resp.status}')
                    failed += 1
                else:
                    retry_err = err or retry_err
                    attempts[msgid] += 1
                    if attempts[msgid] < self.MAX_ATTEMPTS:
                        queue.append(msgid)
                    else:
                        print(f'Giving up on message {msgid} after {self.MAX_ATTEMPTS} attempts: {err!r}')
                        failed += 1

            if msgs:
                cb_proc(msgs)
                done += len(msgs)
            if retry_err:
                self.throttle.backoff(f'HTTP error {retry_err.resp.status}', retry_err.resp.get('retry-after'))
            else:
                self.throttle.success()

            now = time.monotonic()
            if now - lastprint >= 60 or not queue:
                rate = (done + failed) / max(now - start, 1) * 60
                eta = len(queue) / rate if rate else 0
                print(f'Fetched {done}/{total} messages ({failed} failed), {rate:.0f}/min,'
                      f' ETA {eta // 60:.0f}h{eta % 60:02.0f}m')
                lastprint = now

class SqlClient:
    """MariaDB Client"""
    def __init__(self, url: str):
        # Pre-ping replaces pooled connections dropped while idle (ex. during
        # authentication or backoff)
        self.engine = create_engine(url, pool_pre_ping=True)
        # Base.metadata.drop_all(self.engine)
        Base.metadata.create_all(self.engine)

    @staticmethod
    def msghdr(headers, hdr) -> Iterator[str]:
        """Yield all header values, split on ','
        """
        for item in headers:
            if item['name'].lower() == hdr.lower():
                yield item['value']

    @staticmethod
    def getemailid(sess, name: str, addr: str) -> str:
        """Get email_id from database for 'email', inserting it as needed
        """
        if '@' in addr:
            user, domain = addr.rsplit('@', 1)
        else:
            user, domain = addr, ''

        stmt = (select(Addresses.id)
                .join(AddressUsers)
                .join(AddressDomains)
                .join(AddressNames)
                .where(AddressUsers.user == user,
                       AddressDomains.domain == domain,
                       AddressNames.name == name,
                       ))
        res = sess.scalar(stmt)
        if res:
            return res

        # Insert a new item and return its id
        addr_id = sess.scalar(insert(Addresses).values().returning(Addresses.id))
        sess.execute(insert(AddressUsers).values(id=addr_id, user=user))
        sess.execute(insert(AddressDomains).values(id=addr_id, domain=domain))
        sess.execute(insert(AddressNames).values(id=addr_id, name=name))
        return addr_id

    @staticmethod
    def _insert_senders(sess, msg_id: str, headers: str) -> Iterator[dict[str, str | bool]]:
        """Update addresses table and return message_sender relations to insert
        """
        uniq = set()
        h_from = getaddresses(list(SqlClient.msghdr(headers, 'From')))
        h_sender = getaddresses(list(SqlClient.msghdr(headers, 'Sender')))

        if len(h_from) == 1:
            sender_n, sender_a = h_from[0]
            sender_type = 'from'
        elif len(h_sender) == 1:
            sender_n, sender_a = h_sender[0]
            sender_type = 'sender'
        else:
            print(f"Warning: message id {msg_id} has no valid sender, using id")
            sender_n, sender_a = '', f'{msg_id}@gmail.invalid'
            sender_type = 'none'

        sender_id = SqlClient.getemailid(sess, sender_n, sender_a)

        yield {
            'message_id': msg_id,
            'sender_id': sender_id,
            'type': sender_type,
            'primary': True,
        }
        # Dedup on address ids, as the database collation can match different
        # strings (case, accents...) to the same address
        uniq.add((sender_id, sender_type))

        stuples = tuple(((i, 'from') for i in h_from))
        stuples += tuple(((i, 'sender') for i in h_sender))
        for (sname, saddr), stype in stuples:
            sid = SqlClient.getemailid(sess, sname, saddr)
            if (sid, stype) in uniq:
                continue
            yield {
                'message_id': msg_id,
                'sender_id': sid,
                'type': stype,
                'primary': False,
            }
            uniq.add((sid, stype))

    @staticmethod
    def _insert_receivers(sess, msg_id: str, headers: str) -> Iterator[dict[str, str]]:
        uniq = set()
        h_to = getaddresses(list(SqlClient.msghdr(headers, 'To')))
        h_cc = getaddresses(list(SqlClient.msghdr(headers, 'Cc')))

        rtuples = tuple(((i, 'to') for i in h_to))
        rtuples += tuple(((i, 'cc') for i in h_cc))

        for (rname, raddr), rtype in rtuples:
            rid = SqlClient.getemailid(sess, rname, raddr)
            if (rid, rtype) in uniq:
                continue
            yield {
                'message_id': msg_id,
                'receiver_id': rid,
                'type': rtype,
            }
            uniq.add((rid, rtype))

    @staticmethod
    def _insertmsg(
        sess,
        msg: dict,
        msgmaps: list[dict[str, str]],
        labelsmaps: list[dict[str, str]],
        sendersmaps: list[dict[str, str | bool]],
        receiversmaps: list[dict[str, str]],
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments # needs refactor...
        msg_id = msg['id']

        msgmaps.append({
            'id': msg_id,
            'threadId': msg['threadId'],
            'snippet': msg['snippet'],
            'size': msg['sizeEstimate'],
            'recv': msg['internalDate'],
        })

        for label in msg.get('labelIds', []):
            labelsmaps.append({
                'message_id': msg_id,
                'label_id': label,
            })

        sendersmaps.extend(
            SqlClient._insert_senders(sess, msg_id, msg['payload']['headers'])
        )
        receiversmaps.extend(
            SqlClient._insert_receivers(sess, msg_id, msg['payload']['headers'])
        )

    def insertmsg(self, msg: dict[str, str]):
        """Insert a single message into the database
        """
        self.insertmsg_batched([msg])

    def insertmsg_batched(self, msglist: Iterable[dict[str, str]]):
        """Insert a batch of messages into the database
        """
        with Session(self.engine, autobegin=False) as sess:
            with sess.begin():
                msgmaps = []
                labelsmaps = []
                sendersmaps = []
                receiversmaps = []
                for msg in msglist:
                    self._insertmsg(sess, msg, msgmaps, labelsmaps,
                                    sendersmaps, receiversmaps)
                sess.execute(insert(Messages).values(msgmaps))
                if labelsmaps:
                    sess.execute(insert(MessagesLabels).values(labelsmaps))
                if sendersmaps:
                    sess.execute(insert(MessagesSenders).values(sendersmaps))
                if receiversmaps:
                    sess.execute(insert(MessagesReceivers).values(receiversmaps))

    def removemsg_batched(self, msgids: Iterable[str]):
        """Remove a batch of messages from the database
        """
        with Session(self.engine, autobegin=False) as sess:
            with sess.begin():
                sess.execute(delete(MessagesReceivers).where(MessagesReceivers.message_id.in_(msgids)))
                sess.execute(delete(MessagesSenders).where(MessagesSenders.message_id.in_(msgids)))
                sess.execute(delete(MessagesLabels).where(MessagesLabels.message_id.in_(msgids)))
                sess.execute(delete(Messages).where(Messages.id.in_(msgids)))

    def update_labels(self, labels: Iterable[Mapping[str, str]]):
        """Update labels in the database (inserts new ones)
        """
        objs = (
            Labels(
                id=i['id'],
                name=i['name'],
                type=i['type'],
            ) for i in labels
        )
        with Session(self.engine, autobegin=False) as sess:
            with sess.begin():
                for label in objs:
                    sess.merge(label)

    def get_msgids(self) -> set[str]:
        """Get all current msg ids (to skip fetching them)"""
        with Session(self.engine, autobegin=False) as sess:
            with sess.begin():
                stmt = select(Messages.id)
                return set(sess.scalars(stmt))

def main():
    """main"""
    config = Path(__file__).with_name('config.toml')
    if not config.exists():
        print(f'Please copy `{config.name}.example\' to `{config.name}\' and edit it.')
        sys.exit(1)
    with config.open('rb') as fhd:
        backend = SqlClient(tomllib.load(fhd)['sql']['engine'])
    print('*** Getting loaded message IDs...')
    msgids = backend.get_msgids()

    client = GmailClient()
    print('*** Updating labels...')
    backend.update_labels(client.get_labels())

    headers = ['from', 'sender', 'to', 'cc']
    client.proc_msg_batch(backend.insertmsg_batched, headers, msgids)

    print(f'*** Cleaning up {len(msgids)} removed messages...')
    backend.removemsg_batched(msgids)

if __name__ == '__main__':
    main()
