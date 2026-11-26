#!/bin/sh
# Docker entrypoint: apply migrations, optionally seed dev fixtures, then
# run the command given (default: the API server).
set -e

echo "Applying database migrations..."
alembic upgrade head

if [ "$NULL_SEED_DEV_FIXTURES" = "true" ]; then
  echo "Seeding development fixtures..."
  python -m scripts.seed_dev || echo "Seeding skipped (fixtures may already exist)."
fi

exec "$@"
