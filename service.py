import logging
import time

from entity import (
    HardwareFinishColor,
)
from homekey import read_homekey, ProtocolError
from repository import Repository
from util.bfclf import (
    BroadcastFrameContactlessFrontend,
    RemoteTarget,
    activate,
    ISODEPTag,
)
from util.digital_key import DigitalKeyFlow, DigitalKeyTransactionType
from util.ecp import ECP
from util.iso7816 import ISO7816Tag

log = logging.getLogger()


class Service:
    def __init__(
            self,
            clf: BroadcastFrameContactlessFrontend,
            repository: Repository,
            express: bool = True,
            finish: str = "silver",
            flow: str = "fast",
    ) -> None:
        self.repository = repository
        self.clf = clf
        self.express = express in (True, "True", "true", "1")

        try:
            self.hardware_finish_color = HardwareFinishColor[finish.upper()]
        except KeyError:
            self.hardware_finish_color = HardwareFinishColor.BLACK
            log.warning(
                f"HardwareFinish {finish} is not supported. Falling back to {self.hardware_finish_color}"
            )
        try:
            self.flow = DigitalKeyFlow[flow.upper()]
        except KeyError:
            self.flow = DigitalKeyFlow.FAST
            log.warning(
                f"Digital Key flow {flow} is not supported. Falling back to {self.flow}"
            )

        self._run_flag = True

    def on_endpoint_authenticated(self, endpoint):
        """This method will be called when an endpoint is authenticated"""
        # Currently overwritten by accessory.py
        log.info(
            f"++++++++++++++++++++++++++++++++++++++++++++++++++"
        )

    def _read_homekey(self):
        start = time.monotonic()

        remote_target = self.clf.sense(
            RemoteTarget("106A"),
            broadcast=ECP.home(
                identifier=self.repository.get_reader_group_identifier(),
                flag_2=self.express,
            ).pack(),
        )
        if remote_target is None:
            return

        target = activate(self.clf, remote_target)
        if target is None:
            return

        if not isinstance(target, ISODEPTag):
            log.info(
                f"Found non-ISODEP Tag with UID: {target.identifier.hex().upper()}"
            )
            while self.clf.sense(RemoteTarget("106A")) is not None:
                log.info("Waiting for target to leave the field...")
                time.sleep(0.5)
            return

        log.info(f"Got NFC tag {target}")

        tag = ISO7816Tag(target)
        try:
            result_flow, new_issuers_state, endpoint = read_homekey(
                tag,
                issuers=self.repository.get_all_issuers(),
                preferred_versions=[b"\x02\x00"],
                flow=self.flow,
                transaction_code=DigitalKeyTransactionType.UNLOCK,
                reader_identifier=self.repository.get_reader_group_identifier()
                                  + self.repository.get_reader_identifier(),
                reader_private_key=self.repository.get_reader_private_key(),
                key_size=16,
            )

            if new_issuers_state is not None and len(new_issuers_state):
                self.repository.upsert_issuers(new_issuers_state)

            log.info(f"Authenticated endpoint via {result_flow!r}: {endpoint}")

            end = time.monotonic()
            log.info(f"Transaction took {(end - start) * 1000} ms")

            if endpoint is not None:
                self.on_endpoint_authenticated(endpoint)
        except ProtocolError as e:
            log.info(f'Could not authenticate device due to protocol error "{e}"')

        # Let device cool down, wait for ISODEP to drop to consider comms finished
        while target.is_present:
            log.info("Waiting for device to leave the field...")
            time.sleep(0.5)
        log.info("Device left the field. Continuing in 2 seconds...")
        time.sleep(2)
        log.info("Waiting for next device...")

    def run(self):
        if self.repository.get_reader_private_key() in (None, b""):
            raise Exception("Device is not configured via HAP. NFC inactive")

        log.info("Connecting to the NFC reader...")

        if self.clf.device is None:
            raise Exception(
                f"Could not connect to NFC device {self.clf} at {self.clf.path}"
            )

        while self._run_flag:
            self._read_homekey()
