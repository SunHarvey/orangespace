"""Node federation boundary checks; clock injection is not a kernel timing test."""
import time
from unittest.mock import patch
from uuid import uuid4

import pytest
from orangespace_node.federation import ExchangeBody, checked_federation, bindings


def test_node_exchange_rejects_zero_uuid_before_remote_io():
    with pytest.raises(ValueError):
        ExchangeBody(schema=1, exchange_id='00000000-0000-0000-0000-000000000000', exchange_token='A'*43)


def test_issuer_frozen_identity_deadline_not_reanchored_to_node_clock():
    issuer_now = int(time.time())
    ids = {key: str(uuid4()) for key in ('federation_session_id','central_session_id','central_user_id','node_id','legacy_user_id','mapping_id','grant_id')}
    value = dict(ids, epochs=dict(user_epoch=1,node_epoch=1,mapping_epoch=1,grant_epoch=1), expires_at=issuer_now+3600)
    config = dict(node_id=value['node_id'], node_epoch=1)
    # Trusted issuer has already bounded its deadline. A one-second clock
    # difference must not cause the node to recompute that authorization window.
    with patch('orangespace_node.federation.time.time', return_value=issuer_now-1):
        assert checked_federation(value, config) == value
    assert value['expires_at'] == issuer_now+3600


def test_exchange_replay_binding_is_not_cascade_deleted_with_session():
    keys = list(bindings.c.token_digest.foreign_keys)
    assert len(keys) == 1
    assert keys[0].ondelete == 'RESTRICT'


@pytest.mark.parametrize('bad', [True, 1.0, 9007199254740992, -1, 1000, 999])
def test_expiry_type_safe_range_and_elapsed_deadline_rejected(bad):
    ids = {key: str(uuid4()) for key in ('federation_session_id','central_session_id','central_user_id','node_id','legacy_user_id','mapping_id','grant_id')}
    value = dict(ids, epochs=dict(user_epoch=1,node_epoch=1,mapping_epoch=1,grant_epoch=1), expires_at=bad)
    with patch('orangespace_node.federation.time.time', return_value=1000):
        with pytest.raises(ValueError):
            checked_federation(value, dict(node_id=value['node_id'], node_epoch=1))


@pytest.mark.parametrize('expiry', [4601, 9007199254740991])
def test_valid_original_expiry_is_preserved_exactly(expiry):
    ids = {key: str(uuid4()) for key in ('federation_session_id','central_session_id','central_user_id','node_id','legacy_user_id','mapping_id','grant_id')}
    value = dict(ids, epochs=dict(user_epoch=1,node_epoch=1,mapping_epoch=1,grant_epoch=1), expires_at=expiry)
    with patch('orangespace_node.federation.time.time', return_value=1000):
        result = checked_federation(value, dict(node_id=value['node_id'], node_epoch=1))
    assert result is value
    assert result['expires_at'] == expiry


@pytest.mark.parametrize('bad', ['00000000-0000-0000-0000-000000000000', 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA', 'aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa', '{aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa}'])
def test_uuid_is_strict_not_normalized(bad):
    from orangespace_node.federation import canonical
    with pytest.raises(ValueError):
        canonical(bad)
