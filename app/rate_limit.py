"""Shared rate limiter.

A single ``slowapi.Limiter`` instance for the whole application. It must
live here (not in ``app.main``) because routers need the same instance
for their ``@limiter.limit`` decorators, and importing it from
``app.main`` would be circular. Tests disable it via
``limiter.enabled = False`` (see ``tests/conftest.py``); that only works
if every decorator and the app share this one object.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
