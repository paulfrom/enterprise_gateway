"""Explicit synthetic verification algorithms; no real supplier proof."""
import hmac


def verify_hmac_sha256(block, verification_material):
    return hmac.compare_digest(block.signature, hmac.digest(verification_material, block.content.encode(), 'sha256').hex())


def verify_fixture_signature(block, verification_material):
    return hmac.compare_digest(block.signature.encode(), verification_material)
