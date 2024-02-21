#!/bin/bash

# Init the wordpress configuration.
res=$(docker compose run --rm wpcli wp core install --path="/var/www/html" --url=http://localhost --title="test" --admin_user=test --admin_password=test --admin_email=test@test.test 2>&1)

# In case of error stop and print the output
if [ $? -ne 0 ]; then
  echo "$res"
  exit 1
fi

# Check if there is the neeed to activate a plugin/theme
if [ ! -z "$1" ] && [ ! -z "$2" ]; then
  res=$(docker compose run --rm wpcli wp $1 --path="/var/www/html" activate $2 2>&1)
  if [ $? -eq 0 ]; then
    exit 0
  else
    echo "$res"
    exit 1
  fi
else
  exit 0
fi
