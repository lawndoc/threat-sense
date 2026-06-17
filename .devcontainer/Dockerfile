FROM mcr.microsoft.com/devcontainers/typescript-node:24-bookworm

# Install additional OS packages required for building/packaging the extension
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends zip unzip \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
