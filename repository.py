import copy
import hashlib
import json
import logging
from threading import Lock
from typing import List, Optional

from entity import Endpoint, Issuer

log = logging.getLogger()


class Repository:
    """Serves as a way of emulating a storage/database"""

    _configuration: dict
    # _configuration: dict = {
    #     "reader_private_key": "286f0bb7c1cd6ffc6fca1cf17a57de1c789ace446b927af8de1f14915d13ae65",
    #     "reader_identifier": "7c4b46cbd8ac5ecf",
    #     "issuers": {
    #         "a01e4b89ba67d93b": {
    #             "public_key": "53f14c419f2c99ed2ce271c99c914e8c4431ca9e76846221a00f8e5d2f7e7ad1",
    #             "endpoints": {
    #                 "4139b8df8f25": {
    #                     "last_used_at": 1704149147,
    #                     "counter": 31,
    #                     "key_type": 2,
    #                     "public_key": "047516c5683d52a35360bc51fe286c0794f7d7442d271e34c8dcc53dec7ea6aa6a30a79050e2dbc7bd50ad30b3f8486f3dad83a07eb0ee2668b3e52c8661082613",
    #                     "persistent_key": "9640b5140cb6c2a5e025a604cd0774adf7cb9abd5390d328ce8a0ae75514f4cc",
    #                     "enrollments": {
    #                         "hap": {
    #                             "at": 1702517045,
    #                             "payload": "AQECAkB1FsVoPVKjU2C8Uf4obAeU99dELSceNMjcxT3sfqaqajCnkFDi28e9UK0ws/hIbz2tg6B+sO4maLPlLIZhCCYTAwigHkuJumfZOwQBAQ=="
    #                         },
    #                         "attestation": None
    #                     }
    #                 }
    #             }
    #         }
    #     }
    # }
    #     _configuration: dict = {
    #   "reader_private_key": "18922a5d8f26874243a1e532d767058baf7d68426d6d9633ccace79d74fe71d0",
    #   "reader_identifier": "b2e5212106e4549c",
    #   "issuers": {
    #     "aa3b630ce75ed3ad": {
    #       "public_key": "6ff5aa212c76510ad6b527c6d65e5ab27c695249284ff8cb181001511baf94d6",
    #       "endpoints": {
    #         "5105e57b7f29": {
    #           "last_used_at": 0,
    #           "counter": 0,
    #           "key_type": 2,
    #           "public_key": "048bd9509d0f2aa2328a39b5c4ba411b2efb5d64b441bbee8a22e14d9fea4dce35c846859c70744ac1e4402a99ffc3f1663af6bacb17b5b85378d7a0ac849986f4",
    #           "persistent_key": "243cf31005dc73447c4c4a2aa1406d71761297d8d1ba845aa7ac54ba23a5bab8",
    #           "enrollments": {
    #             "hap": {
    #               "at": 1704154332,
    #               "payload": "AQECAkCL2VCdDyqiMoo5tcS6QRsu+11ktEG77ooi4U2f6k3ONchGhZxwdErB5EAqmf/D8WY69rrLF7W4U3jXoKyEmYb0AwiqO2MM517TrQQBAQ=="
    #             },
    #             "attestation": null
    #           }
    #         }
    #       }
    #     }
    #   }
    # }
    _issuers: List[Issuer]

    def __init__(self, config: dict):
        self._configuration = config
        self._reader_private_key = bytes.fromhex("00" * 32)
        self._reader_identifier = bytes.fromhex("00" * 8)
        self._issuers = list()
        self._transaction_lock = Lock()
        self._state_lock = Lock()
        self._load_state_from_file()

    def _load_state_from_file(self):
        try:
            with self._state_lock:
                configuration = self._configuration
                self._reader_private_key = bytes.fromhex(
                    configuration.get("reader_private_key", "00" * 32)
                )
                self._reader_identifier = bytes.fromhex(
                    configuration.get("reader_identifier", "00" * 8)
                )
                self._issuers = [
                    Issuer.from_dict(issuer)
                    for _, issuer in configuration.get("issuers", {}).items()
                ]
        except Exception:
            log.exception(
                f"Could not load Home Key configuration. Assuming that device is not yet configured..."
            )
            pass

    def _save_state_to_file(self):
        with self._state_lock:
            self._configuration = {
                "reader_private_key": self._reader_private_key.hex(),
                "reader_identifier": self._reader_identifier.hex(),
                "issuers": {
                    issuer.id.hex(): issuer.to_dict() for issuer in self._issuers
                },
            }

    def _refresh_state(self):
        self._save_state_to_file()
        self._load_state_from_file()

    def get_reader_private_key(self):
        return self._reader_private_key

    def set_reader_private_key(self, reader_private_key):
        with self._transaction_lock:
            self._reader_private_key = reader_private_key
            self._refresh_state()

    def get_reader_identifier(self):
        return self._reader_identifier

    def set_reader_identifier(self, reader_identifier):
        with self._transaction_lock:
            self._reader_identifier = reader_identifier
            self._refresh_state()

    def get_reader_group_identifier(self):
        return (
                   hashlib.sha256("key-identifier".encode() + self.get_reader_private_key())
               ).digest()[:8]

    def get_all_issuers(self):
        return copy.deepcopy([i for i in self._issuers])

    def get_all_endpoints(self):
        return copy.deepcopy(
            [endpoint for issuer in self._issuers for endpoint in issuer.endpoints]
        )

    def get_endpoint_by_public_key(self, public_key: bytes) -> Optional[Endpoint]:
        return next(
            (
                endpoint
                for endpoint in self.get_all_endpoints()
                if endpoint.public_key == public_key
            ),
            None,
        )

    def get_endpoint_by_id(self, id) -> Optional[Endpoint]:
        return next(
            (endpoint for endpoint in self.get_all_endpoints() if endpoint.id == id),
            None,
        )

    def get_issuer_by_public_key(self, public_key) -> Optional[Issuer]:
        return next(
            (
                issuer
                for issuer in self.get_all_issuers()
                if issuer.public_key == public_key
            ),
            None,
        )

    def get_issuer_by_id(self, id) -> Optional[Issuer]:
        return next(
            (issuer for issuer in self.get_all_issuers() if issuer.id == id), None
        )

    def remove_issuer(self, issuer: Issuer):
        with self._transaction_lock:
            issuers = [i for i in copy.deepcopy(self._issuers) if i.id != issuer.id]
            self._issuers = issuers
            self._refresh_state()

    def upsert_issuer(self, issuer: Issuer):
        with self._transaction_lock:
            issuer = copy.deepcopy(issuer)
            issuers = [
                (i if i.id != issuer.id else issuer)
                for i in copy.deepcopy(self._issuers)
            ]
            if issuer not in issuers:
                issuers.append(issuer)
            self._issuers = issuers
            self._refresh_state()

    def upsert_endpoint(self, issuer_id, endpoint: Endpoint):
        with self._transaction_lock:
            issuer = next(
                (issuer for issuer in self._issuers if issuer.id == issuer_id), None
            )
            endpoints = [
                (e if e.id != endpoint.id else endpoint) for e in issuer.endpoints
            ]
            if endpoint not in endpoints:
                endpoints.append(endpoint)
            issuer.endpoints = endpoints
            self._refresh_state()

    def upsert_issuers(self, issuers: List[Issuer]):
        issuers = {issuer.id: copy.deepcopy(issuer) for issuer in issuers}
        with self._transaction_lock:
            iss = [issuers.get(i.id, i) for i in copy.deepcopy(self._issuers)]
            for issuer in issuers.values():
                if issuer not in iss:
                    iss.append(issuer)
            self._issuers = iss
            self._refresh_state()
