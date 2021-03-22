#!/bin/bash

# Remove any container associated to docker-compose
docker-compose rm -f > /dev/null 2>&1

# Start Docker compose in backgound
res=$(docker-compose up -d 2>&1)

# If everything is okay, print 'ok' else the error
if [ $? -eq 0 ]; then
  echo "ok"
else
  echo "$res"
fi