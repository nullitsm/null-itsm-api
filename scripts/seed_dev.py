"""Seed development fixtures (CLI).

Usage:  python -m scripts.seed_dev
Requires NULL_SEED_DEV_FIXTURES=true and the owner database URL.
"""

from __future__ import annotations

import sys

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config import get_settings
from app.seed import seed_dev_fixtures


def main() -> int:
    settings = get_settings()
    if not settings.seed_dev_fixtures:
        print("Refusing: NULL_SEED_DEV_FIXTURES is not true. Dev fixtures are never seeded blindly.")
        return 1
    engine = create_engine(settings.database_owner_url)
    session = sessionmaker(bind=engine)()
    try:
        created = seed_dev_fixtures(session)
        for org in created:
            print(f"Seeded fixture organization: {org.name} ({org.slug})")
        if not created:
            print("Fixture organizations already exist; nothing to do.")
        return 0
    finally:
        session.close()


if __name__ == "__main__":
    sys.exit(main())
