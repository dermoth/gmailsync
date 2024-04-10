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
from pathlib import Path
from email.utils import getaddresses
from collections.abc import Generator, Iterable, Iterator,Mapping
from typing import Literal, Optional
#from typing import List, Optional

from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

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
    user: Mapped[str] = mapped_column(VARCHAR(253, charset='ascii'), index=True)
    address: Mapped["Addresses"] = relationship()

class AddressDomains(Base):
    "Email Domains table"
    __tablename__ = 'address_domains'

    id: Mapped[int] = mapped_column(ForeignKey('addresses.id'), primary_key=True)
    # Considering the MAIL FROM/RCPT TO 255 length limit
    domain: Mapped[str] = mapped_column(VARCHAR(253, charset='ascii'), index=True)
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
    # Per the FRC is there is more than one From addr there MUST be one Sender
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

class GmailClient:
    """Gmail Client"""
    SCRIPT = Path(__file__)
    CLIENT = SCRIPT.with_name('gmailsync_client.json')
    # If modifying these scopes, delete the file token.json.
    SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

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

        1. Click on the link and get the token form the OAuth page

        2. Enter the authorization key in the prompt below
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
        self.userid=userid

    def _yield_msglist_batch(self, messages, batchsz=100):
        req = messages.list(userId=self.userid, maxResults=batchsz)
        resp = req.execute()
        lst = resp.get('messages', [])
        while lst:
            yield lst
            req = messages.list_next(req, resp)
            if not req:
                break
            resp = req.execute()
            lst = resp.get('messages', [])

    def get_labels(self) -> list[dict[str, str]]:
        """Return all labels for inbox
        """
        # pylint: disable=no-member
        res = self.service.users().labels().list(userId=self.userid).execute()
        return res.get('labels', [])

    def proc_msg_batch(self, cb_recv, cb_proc, headers, skip: Optional[set] = None):
        """Process messages in batches
        Skip msgid's in skip, and remove them from the set
        """
        if not skip:
            skip = set()
        messages = self.service.users().messages()  # pylint: disable=no-member
        for msgs in self._yield_msglist_batch(messages):
            batch = self.service.new_batch_http_request()  # pylint: disable=no-member
            for msg in msgs:
                if msg['id'] in skip:
                    skip.remove(msg['id'])
                    continue
                batch.add(
                    messages.get(
                        userId=self.userid,
                        id=msg['id'],
                        format='metadata',
                        metadataHeaders=headers,
                    ),
                    callback=cb_recv,
                )
            batch.execute()
            cb_proc()

class SqlClient:
    """MariaDB Client"""
    ENGINE = 'mariadb+mariadbconnector://<USERNAME>:<PASSWORD>@<HOSTNAME>/<DATABASE>'

    def __init__(self):
        self.engine = create_engine(self.ENGINE)
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
        # Need to review RFCs here, for now allow only ascii
        # In any case unexpected data should be ignored/replaced
        addr = addr.encode('ascii', errors='replace').decode('ascii')
        if '@' in addr:
            user, domain = addr.split('@')
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
        uniq.add((sender_n, sender_a, sender_type))

        stuples = tuple(((i, 'from') for i in h_from))
        stuples += tuple(((i, 'sender') for i in h_sender))
        for (sname, saddr), stype in stuples:
            if (sname, saddr, stype) in uniq:
                continue
            sid = SqlClient.getemailid(sess, sname, saddr)
            yield {
                'message_id': msg_id,
                'sender_id': sid,
                'type': stype,
                'primary': False,
            }
            uniq.add((sname, saddr, stype))

    @staticmethod
    def _insert_receivers(sess, msg_id: str, headers: str) -> Iterator[dict[str, str]]:
        uniq = set()
        h_to = getaddresses(list(SqlClient.msghdr(headers, 'To')))
        h_cc = getaddresses(list(SqlClient.msghdr(headers, 'Cc')))

        rtuples = tuple(((i, 'to') for i in h_to))
        rtuples += tuple(((i, 'cc') for i in h_cc))

        for (rname, raddr), rtype in rtuples:
            if (rname, raddr, rtype) in uniq:
                continue
            rid = SqlClient.getemailid(sess, rname, raddr)
            yield {
                'message_id': msg_id,
                'receiver_id': rid,
                'type': rtype,
            }
            uniq.add((rname, raddr, rtype))

    @staticmethod
    def _insertmsg(
        sess,
        msg: dict,
        msgmaps: list[dict[str, str]],
        labelsmaps: list[dict[str, str]],
        sendersmaps: list[dict[str, str | bool]],
        receiversmaps: list[dict[str, str]],
    ):  # pylint: disable=too-many-arguments # meeds refactor...
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
        """Remove a batch of messages into the database
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

class BatchProcessor:
    """Batch processor helper class"""
    def __init__(self, cb_proc, update_sz=1000, update_delay=60):
        self.cb_proc = cb_proc
        self.messages = []
        self.count = 0
        self.batchcount = 0
        self.update_sz = update_sz
        self.lastupd = int(time.time())
        self.update_delay = update_delay

    def countreqs(self, count):
        """Increment batch counter by count, backoff as needed"""

        self.batchcount += count
        if self.batchcount >= self.update_sz:
            now = int(time.time())
            elapsed = now - self.lastupd
            # update_delay is for update_sz requests, adjust
            adjdelay = self.batchcount / self.update_sz * self.update_delay
            sleep = adjdelay - elapsed
            if sleep > 0:
                print(f'Processed {self.count} messages, sleeping {sleep:.2f} seconds...', end=' ')
                sys.stdout.flush()
                time.sleep(sleep)
                print('Done!')
            else:
                print(f'Processed {self.count} messages')
            self.batchcount = 0
            self.lastupd = int(time.time())

    def recv(self, req_id, msg, exp):  # pylint: disable=unused-argument
        """Callback to receive and accumulates messages
        """
        if exp:
            print(exp)
            return

        self.messages.append(msg)
        self.count += 1

    def proc(self):
        """Callback to process a batch of messages
        """
        # Each list results in proc() call so count it here
        count = 1
        if self.messages:
            count += len(self.messages)
            self.cb_proc(self.messages)
            self.messages = []

        self.countreqs(count)

def main():
    """main"""
    backend = SqlClient()
    print('*** Getting loaded message IDs...')
    msgids = backend.get_msgids()

    client = GmailClient()
    proc = BatchProcessor(backend.insertmsg_batched)
    print('*** Updating labels...')
    backend.update_labels(client.get_labels())

    headers = ['from', 'sender', 'to', 'cc']
    print('*** Inserting messages...')
    client.proc_msg_batch(proc.recv, proc.proc, headers, skip=msgids)

    print(f'*** Cleaning up {len(msgids)} removed messages...')
    backend.removemsg_batched(msgids)

if __name__ == '__main__':
    main()
