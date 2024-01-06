import base64
import hashlib
import logging
import os
import time
from typing import Collection, List, Optional, Tuple

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF

from entity import (
    Context,
    Endpoint,
    Enrollment,
    Enrollments,
    Interface,
    Issuer,
    KeyType,
)
from util.crypto import get_ec_key_public_points, load_ec_public_key_from_bytes
from util.digital_key import (
    DigitalKeyFlow,
    DigitalKeySecureContext,
    DigitalKeyTransactionFlags,
    DigitalKeyTransactionType,
)
from util.generic import chunked, get_tlv_tag
from util.iso18013 import ISO18013SecureContext
from util.iso7816 import ISO7816, ISO7816Application, ISO7816Command, ISO7816Tag
from util.ndef import NDEFMessage, NDEFRecord
from util.structable import pack
from util.tlv import BERTLV as TLV

log = logging.getLogger()


class ProtocolError(Exception):
    pass

class EndpointNotFound(Exception):
    pass



COSE_CONTEXT = "Signature1"
COSE_AAD = b""

# Random numbers presumably used to provide entropy.
# Coincidentally, they're valid UNIX epochs
READER_CONTEXT = int(1096652137).to_bytes(4, "big")
DEVICE_CONTEXT = int(1317567308).to_bytes(4, "big")


def get_endpoints_from_issuers(issuers: List[Issuer]):
    return (e for i in issuers for e in i.endpoints)


def generate_ec_key_if_provided_is_none(
        private_key: Optional[ec.EllipticCurvePrivateKey],
):
    return (
        ec.derive_private_key(int.from_bytes(private_key, "big"), ec.SECP256R1())
        if private_key
        else ec.generate_private_key(ec.SECP256R1())
    )


def fast_auth(
        tag: ISO7816Tag,
        device_protocol_versions: List[bytes],
        protocol_version: bytes,
        interface: int,
        flags: bytes,
        reader_identifier: bytes,
        reader_public_key: ec.EllipticCurvePublicKey,
        reader_ephemeral_public_key: ec.EllipticCurvePublicKey,
        transaction_identifier: bytes,
        issuers: List[Issuer],
        key_size=16,
) -> Tuple[
    ec.EllipticCurvePublicKey, Optional[Endpoint], Optional[DigitalKeySecureContext]
]:
    (
        reader_ephemeral_public_key_x,
        reader_ephemeral_public_key_y,
    ) = get_ec_key_public_points(reader_ephemeral_public_key)
    reader_ephemeral_public_key_bytes = bytes(
        [0x04, *reader_ephemeral_public_key_x, *reader_ephemeral_public_key_y]
    )
    reader_public_key_x, _ = get_ec_key_public_points(reader_public_key)

    command_tlv = [
        TLV(0x5C, value=protocol_version),
        TLV(0x87, value=reader_ephemeral_public_key_bytes),
        TLV(0x4C, value=transaction_identifier),
        TLV(0x4D, value=reader_identifier),
    ]
    command_data = pack(command_tlv)

    command = ISO7816Command(
        cla=0x80, ins=0x80, p1=flags[0], p2=flags[1], data=command_data, le=None
    )
    log.info(f"AUTH0 CMD = {command}")
    response = tag.transceive(command)
    if response.sw != (0x90, 0x00):
        raise ProtocolError(f"AUTH0 INVALID STATUS {response.sw}")
    log.info(f"AUTH0 RES = {response}")
    tlv_array = TLV.unpack_array(response.data)

    endpoint_ephemeral_public_key_tag = get_tlv_tag(tlv_array, 0x86)
    if endpoint_ephemeral_public_key_tag is None:
        raise ProtocolError(
            "Response does not contain endpoint_ephemeral_public_key_tag 0x86"
        )

    endpoint_ephemeral_public_key = load_ec_public_key_from_bytes(
        endpoint_ephemeral_public_key_tag
    )
    endpoint_ephemeral_public_key_x, _ = get_ec_key_public_points(
        endpoint_ephemeral_public_key
    )

    returned_cryptogram = get_tlv_tag(tlv_array, 0x9D)
    if returned_cryptogram is None:
        return endpoint_ephemeral_public_key, None, None

    endpoint = None
    # FAST gives us no way to find out the identity of endpoint from the data for security reasons,
    # so we have to iterate over all provisioned endpoints and hope that it's there
    log.info("Searching for an endpoint with matching cryptogram...")
    for endpoint in get_endpoints_from_issuers(issuers):
        k_persistent = endpoint.persistent_key
        endpoint_public_key_bytes = endpoint.public_key
        endpoint_public_key: ec.EllipticCurvePublicKey = load_ec_public_key_from_bytes(
            endpoint_public_key_bytes
        )
        endpoint_public_key_x, _ = get_ec_key_public_points(endpoint_public_key)

        # Whoever did this. Did that help? ;)
        info_material = (
            reader_public_key_x,
            Context.VOLATILE_FAST,
            reader_identifier,
            endpoint_public_key_x,
            interface,
            TLV(0x5C, value=device_protocol_versions),
            TLV(0x5C, value=protocol_version),
            reader_ephemeral_public_key_x,
            transaction_identifier,
            flags,
            endpoint_ephemeral_public_key_x,
        )

        info = pack(info_material)

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=key_size * 4,
            salt=None,
            info=info,
        ).derive(k_persistent)
        kcmac = hkdf[: key_size * 1]
        kenc = hkdf[key_size * 1: key_size * 2]
        kmac = hkdf[key_size * 2: key_size * 3]
        krmac = hkdf[key_size * 3:]
        calculated_cryptogram = kcmac
        log.info(
            f"Endpoint({endpoint.id.hex()}): {returned_cryptogram.hex()=} ? {calculated_cryptogram.hex()=}"
        )
        if returned_cryptogram == calculated_cryptogram:
            log.info(
                f"Cryptograms match for Endpoint({endpoint.id.hex()}): {kcmac.hex()=} {kenc.hex()=} {kmac.hex()=} {krmac.hex()=};"
            )
            return (
                endpoint_ephemeral_public_key,
                endpoint,
                DigitalKeySecureContext(tag, kenc, kmac, krmac),
            )
        else:
            endpoint = None
    return endpoint_ephemeral_public_key, endpoint, None


def select_applet(tag: ISO7816Tag, applet=ISO7816Application.HOME_KEY):
    command = ISO7816.select_aid(applet)
    log.info(f"SELECT CMD = {command}")
    response = tag.transceive(command)
    if response.sw != (0x90, 0x00):
        raise ProtocolError(
            f"Could not select {applet} {hex(response.sw1)} {hex(response.sw2)}"
        )
    log.info(f"SELECT RES = {response}")
    return response.data


def control_flow(tag: ISO7816Tag, p1=0x01, p2=0x00):
    command = ISO7816Command(cla=0x80, ins=0x3C, p1=p1, p2=p2, data=None, le=None)
    log.info(f"OP_CONTROL_FLOW CMD = {command}")
    response = tag.transceive(command)
    log.info(f"OP_CONTROL_FLOW RES = {response}")
    return response.data


def perform_authentication_flow(
        tag: ISO7816Tag,
        flow: DigitalKeyFlow,
        reader_identifier: bytes,
        reader_private_key: ec.EllipticCurvePrivateKey,
        reader_ephemeral_private_key: ec.EllipticCurvePrivateKey,
        attestation_exchange_common_secret: bytes,
        protocol_version: bytes,
        device_protocol_versions: List[bytes],
        transaction_identifier: bytes,
        flags: bytes,
        interface: int,
        issuers: List[Issuer],
        key_size=16,
) -> Tuple[DigitalKeyFlow, Optional[Issuer], Optional[Endpoint]]:
    """Returns an Endpoint if one was found and successfully authenticated.
    Returns an Issuer if endpoint was authenticated via Attestation
    """
    reader_public_key = reader_private_key.public_key()
    reader_public_key_x, reader_public_key_y = get_ec_key_public_points(
        reader_public_key
    )
    log.info(
        f"Reader public key: x={reader_public_key_x.hex()} y={reader_public_key_y.hex()}"
    )

    reader_ephemeral_public_key = reader_ephemeral_private_key.public_key()

    log.info(f"{protocol_version.hex()=}")

    endpoint_ephemeral_public_key, endpoint, secure = fast_auth(
        tag=tag,
        device_protocol_versions=device_protocol_versions,
        protocol_version=protocol_version,
        interface=interface,
        flags=flags,
        reader_identifier=reader_identifier,
        reader_public_key=reader_public_key,
        reader_ephemeral_public_key=reader_ephemeral_public_key,
        transaction_identifier=transaction_identifier,
        issuers=issuers,
        key_size=key_size,
    )

    if endpoint is not None and flow <= DigitalKeyFlow.FAST:
        return DigitalKeyFlow.FAST, None, endpoint

    raise EndpointNotFound(
        f"Could not select {reader_identifier=}"
    )


def read_homekey(
        tag: ISO7816Tag,
        reader_identifier: bytes,
        reader_private_key: bytes,
        issuers: List[Issuer],
        preferred_versions: Collection[bytes] = None,
        flow=DigitalKeyFlow.FAST,
        transaction_code: DigitalKeyTransactionType = DigitalKeyTransactionType.UNLOCK,
        # Generated at random if not provided
        reader_ephemeral_private_key: Optional[bytes] = None,
        # Generated at random if not provided
        transaction_identifier: Optional[bytes] = None,
        # Generated at random if not provided
        attestation_exchange_common_secret: Optional[bytes] = None,
        interface=Interface.CONTACTLESS,
        key_size=16,
) -> Tuple[DigitalKeyFlow, List[Issuer], Optional[Endpoint]]:
    """
    Returns a list representing new configured issuer state
    and an optional endpoint in case authentication has been successful
    """
    transaction_flags = {
        DigitalKeyTransactionFlags.FAST
        if flow <= DigitalKeyFlow.FAST
        else DigitalKeyTransactionFlags.STANDARD
    }
    flags = bytes([sum(transaction_flags), transaction_code])

    response = select_applet(tag, applet=ISO7816Application.HOME_KEY)
    tlv_array = TLV.unpack_array(response)
    log.info(f"{reader_identifier.hex()=}")

    versions_tag = get_tlv_tag(tlv_array, 0x5C)
    if versions_tag is None:
        raise ProtocolError(
            "Response does not contain supported version list at tag 0x5C"
        )

    device_protocol_versions = [ver for ver in chunked(versions_tag, 2)]
    preferred_versions = preferred_versions or []
    for preferred_version in preferred_versions:
        if preferred_version in device_protocol_versions:
            protocol_version = preferred_version
            log.info(f"Choosing preferred version {protocol_version}")
            break
    else:
        protocol_version = device_protocol_versions[0]
        log.info(f"Defaulting to the newest available version {protocol_version}")
    if protocol_version != b"\x02\x00":
        raise ProtocolError("Only officially supported protocol version is 0200")

    reader_private_key = ec.derive_private_key(
        int.from_bytes(reader_private_key, "big"), ec.SECP256R1()
    )

    result_flow, issuer, endpoint = perform_authentication_flow(
        tag=tag,
        flow=flow,
        reader_identifier=reader_identifier,
        reader_private_key=reader_private_key,
        reader_ephemeral_private_key=generate_ec_key_if_provided_is_none(
            reader_ephemeral_private_key
        ),
        attestation_exchange_common_secret=attestation_exchange_common_secret
                                           or os.urandom(32),
        protocol_version=protocol_version,
        device_protocol_versions=device_protocol_versions,
        transaction_identifier=transaction_identifier or os.urandom(16),
        flags=flags,
        interface=interface,
        issuers=issuers,
        key_size=key_size,
    )
    if endpoint is not None:
        endpoint.last_used_at = int(time.time())
        endpoint.counter += 1

    if issuer and endpoint not in get_endpoints_from_issuers(issuers):
        issuer.endpoints.append(endpoint)

    # Notify about transaction completion.
    if result_flow != DigitalKeyFlow.ATTESTATION:
        control_flow(tag)

    return result_flow, issuers, endpoint
