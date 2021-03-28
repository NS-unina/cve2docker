#!/bin/bash

# Remove any container associated to docker-compose
docker-compose rm -f >/dev/null 2>&1

# Start Docker compose in background
docker-compose up -d

# If everything is okay, print 'ok' else the error
if [ $? -eq 0 ]; then
  exit 0
else
  exit 1
fi
