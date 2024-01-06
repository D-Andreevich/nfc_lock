import logging
import sys

from homekey import EndpointNotFound
from util.bfclf import BroadcastFrameContactlessFrontend
from repository import Repository
from service import Service


def load_configuration() -> dict:
    return {
        "logging": {
            "level": 20
        },
        "nfc": {
            "port": "usbserial-110",
            "driver": "pn532",
            "broadcast": False
        },
        "homekey": {
            "express": True,
            "finish": "black",
            "flow": "fast"
        }
    }


def home_key_configs():
    return [
        {
            "reader_private_key": "18922a5d8f26874243a1e532d767058baf7d68426d6d9633ccace79d74fe71d0",
            "reader_identifier": "f80252e2f99d5bb8",
            "issuers": {
                "aa3b630ce75ed3ad": {
                    "public_key": "6ff5aa212c76510ad6b527c6d65e5ab27c695249284ff8cb181001511baf94d6",
                    "endpoints": {
                        "5105e57b7f29": {
                            "last_used_at": 1704160625,
                            "counter": 1,
                            "key_type": 2,
                            "public_key": "048bd9509d0f2aa2328a39b5c4ba411b2efb5d64b441bbee8a22e14d9fea4dce35c846859c70744ac1e4402a99ffc3f1663af6bacb17b5b85378d7a0ac849986f4",
                            "persistent_key": "9b6c8a27c5ceb09d86ab2c510fd09c68a24be2d97160425c8034e2615560c523",
                            "enrollments": {
                                "hap": {
                                    "at": 1704160607,
                                    "payload": "AQECAkCL2VCdDyqiMoo5tcS6QRsu+11ktEG77ooi4U2f6k3ONchGhZxwdErB5EAqmf/D8WY69rrLF7W4U3jXoKyEmYb0AwiqO2MM517TrQQBAQ=="
                                },
                                "attestation": None
                            }
                        }
                    }
                }
            }
        },
        {
            "reader_private_key": "2f80988fe90a0370e38f1e01c986eca0f2ca1c7089b78ce41caf8d872cc22ddd",
            "reader_identifier": "1b625852e0465804",
            "issuers": {
                "a01e4b89ba67d93b": {
                    "public_key": "53f14c419f2c99ed2ce271c99c914e8c4431ca9e76846221a00f8e5d2f7e7ad1",
                    "endpoints": {
                        "b8be5f5abacf": {
                            "last_used_at": 1704158695,
                            "counter": 1,
                            "key_type": 2,
                            "public_key": "04f55c9cfca561ee4628e697d38e7a68d00bb6cc7e0135e753a21fc485ee9c2d91cee620a54786ddb1add5cd62e3b058a6e2709c01554f8954fffbdc78e63e1120",
                            "persistent_key": "206c31d1059e1882623d7ceb2dc352cdd461e9ce89633da5c17697e0a863f9c0",
                            "enrollments": {
                                "hap": {
                                    "at": 1704158685,
                                    "payload": "AQECAkD1XJz8pWHuRijml9OOemjQC7bMfgE151OiH8SF7pwtkc7mIKVHht2xrdXNYuOwWKbicJwBVU+JVP/73HjmPhEgAwigHkuJumfZOwQBAQ=="
                                },
                                "attestation": None
                            }
                        }
                    }
                }
            }
        }
    ]


def configure_logging(config: dict):
    log = logging.getLogger()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)8s] %(module)-18s:%(lineno)-4d %(message)s"
    )
    hdlr = logging.StreamHandler(sys.stdout)
    log.setLevel(config.get("level", logging.INFO))
    hdlr.setFormatter(formatter)
    log.addHandler(hdlr)
    return log


def configure_nfc_device(config: dict):
    clf = BroadcastFrameContactlessFrontend(
        path=f"tty:{config['port']}:{config['driver']}",
    )
    return clf


def configure_homekey_service(config: dict, nfc_device, repository: Repository):
    service = Service(
        nfc_device,
        repository=repository,
        express=config.get("express", True),
        finish=config.get("finish"),
        flow=config.get("flow"),
    )
    return service


def main():
    config = load_configuration()
    log = configure_logging(config["logging"])

    nfc_device = configure_nfc_device(config["nfc"])

    for config_item in home_key_configs():
        try:
            repository = Repository(config_item)
            homekey_service = configure_homekey_service(config["homekey"], nfc_device, repository)

            homekey_service.run()
        except EndpointNotFound as e:
            log.warning(f"next device --------------------------------------{e}")
            pass



if __name__ == "__main__":
    main()
