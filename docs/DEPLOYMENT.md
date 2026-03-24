# Hound Deployment Guide

This guide covers production deployment for the Hound SaaS stack.

## Overview

Hound runs on the DigitalOcean droplet at `/opt/hound/` with Docker Compose:

- `api` and `worker` share the same backend image
- `frontend` uses its own image
- GitHub Actions publishes images to GHCR on push to the active production branch (`feature/surface-scan` today, `main` if the repo later flips)
- Production rollout stays manual: pull the desired image tags on the droplet, then recreate the containers

## Images

Published container images:

- `ghcr.io/firepan-labs/hound-app`
- `ghcr.io/firepan-labs/hound-frontend`

Compose image env vars:

- `HOUND_APP_IMAGE`
- `HOUND_FRONTEND_IMAGE`

Defaults in `docker-compose.yml` point at local image names for development:

- `hound-app:local`
- `hound-frontend:local`

## CI Publish Flow

The `publish-images.yml` workflow runs on:

- push to `feature/surface-scan`
- push to `main`
- `workflow_dispatch`

For each run it publishes:

- `:latest` for the default branch
- `:<branch-name>` for the pushed branch
- `:<short-sha>` for the exact commit

Use the short SHA tags for explicit production rollouts and rollback safety.

## One-Time Droplet Setup

Log the droplet into GHCR before the first pull-based deploy:

```bash
cd /opt/hound
echo "$GHCR_TOKEN" | sudo docker login ghcr.io -u <github-username> --password-stdin
```

If the package visibility stays private, use a GitHub token with package read access.

## Normal Production Deploy

Update the checkout first so the droplet has the latest compose file and docs:

```bash
cd /opt/hound
sudo git pull
```

Deploy the latest default-branch images:

```bash
export HOUND_APP_IMAGE=ghcr.io/firepan-labs/hound-app:latest
export HOUND_FRONTEND_IMAGE=ghcr.io/firepan-labs/hound-frontend:latest

sudo -E docker compose pull api worker frontend
sudo -E docker compose up -d --no-deps api worker frontend
```

Deploy a specific published commit:

```bash
export HOUND_APP_IMAGE=ghcr.io/firepan-labs/hound-app:<short-sha>
export HOUND_FRONTEND_IMAGE=ghcr.io/firepan-labs/hound-frontend:<short-sha>

sudo -E docker compose pull api worker frontend
sudo -E docker compose up -d --no-deps api worker frontend
```

Use `--no-deps` only when `db` and `redis` are already healthy and the deploy is just a new app image.

## Break-Glass Local Rebuild

If GHCR publish is unavailable, the droplet can still build locally. This is slower and should not be the default path.

```bash
cd /opt/hound
sudo git pull
DOCKER_BUILDKIT=0 sudo docker compose up -d --build api frontend
sudo docker compose up -d --no-build worker
```

The `DOCKER_BUILDKIT=0` fallback exists for low-memory droplets. Prefer the GHCR pull path whenever possible.

## Rollback

Redeploy the previous known-good image tag:

```bash
export HOUND_APP_IMAGE=ghcr.io/firepan-labs/hound-app:<previous-short-sha>
export HOUND_FRONTEND_IMAGE=ghcr.io/firepan-labs/hound-frontend:<previous-short-sha>

sudo -E docker compose pull api worker frontend
sudo -E docker compose up -d --no-deps api worker frontend
```

## Verification

```bash
sudo docker compose ps
sudo docker compose logs --tail=100 api
sudo docker compose logs --tail=100 worker
curl -s https://api.firepan.com/health
```

## Build Optimizations

The repo now uses:

- backend `.dockerignore` to exclude `.venv`, tests, docs, and the embedded frontend tree from backend builds
- frontend `.dockerignore` to exclude `node_modules` and `.next`
- a multi-stage backend Dockerfile so runtime images do not keep `gcc` or `libpq-dev`
- a shared backend image for both `api` and `worker`
