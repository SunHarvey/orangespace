"""Explicit local inventory submission. Injected transports are local tests only."""
import json
import os
import stat
import re
from urllib.parse import urlsplit
import httpx
from sqlalchemy import select
from .database import User
from orangespace_control.security import canonical
from orangespace_control.config import unique_object


def load_machine_config(path):
    fd=None
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077 or info.st_nlink!=1 or info.st_size>16384:
            raise ValueError()
        with os.fdopen(fd,'r') as stream:
            fd=None
            data=json.load(stream,object_pairs_hook=unique_object)
        if set(data)!={'origin','token','node_id','node_epoch','config_revision'}:
            raise ValueError()
        validate(data)
        return data
    except (OSError,ValueError,TypeError,AttributeError):
        raise ValueError('invalid protected machine configuration') from None
    finally:
        if fd is not None: os.close(fd)


def validate(config):
    origin=config['origin']; parsed=urlsplit(origin)
    if parsed.scheme!='https' or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.path or parsed.query or parsed.fragment or origin!='https://'+parsed.netloc or any(ord(c)<=32 for c in origin):
        raise ValueError('invalid machine origin')
    canonical(config['node_id'])
    if not isinstance(config['token'],str) or not re.fullmatch('[A-Za-z0-9_-]{43}',config['token']):
        raise ValueError('invalid machine credential')
    for k in ('node_epoch','config_revision'):
        if type(config[k]) is not int or not 1<=config[k]<=9007199254740991:
            raise ValueError('invalid machine epoch')


async def submit_inventory(engine,config,legacy_user_id,request_id,*,transport=None):
    validate(config)
    canonical(legacy_user_id);canonical(request_id)
    # Select only the actual local primary key, never hashes or file content.
    with engine.connect() as conn:
        if conn.execute(select(User.id).where(User.id==legacy_user_id)).first() is None:
            raise ValueError('local identity absent')
    payload=dict(schema=1,node_id=config['node_id'],node_epoch=config['node_epoch'],config_revision=config['config_revision'],legacy_user_id=legacy_user_id,request_id=request_id)
    async with httpx.AsyncClient(verify=True,follow_redirects=False,timeout=10,transport=transport,trust_env=False) as client:
        response=await client.post(config['origin']+'/control/v1/internal/identity-evidence',json=payload,headers={'Authorization':'Bearer '+config['token']})
        if response.status_code!=201:
            raise ValueError('inventory submission rejected')
        return response.json()
