#!/bin/bash

# Replace the #_ in the install sql with j_
res=$(docker-compose exec -T joomla sed -i 's/#_/j/g' /var/www/html/installation/sql/mysql/joomla.sql 2>&1)

if [ $? -ne 0 ]; then
  echo "$res"
  exit 1
fi

# Running Joomla install SQL
res=$(docker-compose exec -T db mysql -u root -proot joomla <./config/joomla/mysql/joomla.sql 2>&1)

if [ $? -ne 0 ]; then
  echo "$res"
  exit 1
fi

# Adding root user
res=$(docker-compose exec -T db mysql -uroot -proot joomla <./config/mysql/init.sql 2>&1)

if [ $? -ne 0 ]; then
  echo "$res"
  exit 1
fi

# Deleting installation directory
res=$(docker-compose exec -T joomla rm -Rf /var/www/html/installation 2>&1)
res=$(rm -R ./config/joomla/mysql 2>&1)

if [ $? -ne 0 ]; then
  echo "$res"
  exit 1
fi

# Install the extension
if [ ! -z "$1" ]; then

  res=$(docker-compose exec -T joomla php /var/www/html/cli/install-joomla-extension.php --package="/var/www/html/work_directory/$1" 2>&1)

  # Retry if fails
  if [ $? -ne 0 ]; then
    res=$(docker-compose exec -T joomla php /var/www/html/cli/install-joomla-extension.php --package="/var/www/html/work_directory/$1" 2>&1)
  fi

  if [ $? -eq 0 ]; then
    # Adjust permission
    docker-compose exec -T joomla chmod -R 777 /var/www/html/administrator/components >/dev/null 2>&1
    docker-compose exec -T joomla chmod -R 777 /var/www/html/media >/dev/null 2>&1
    exit 0
  else
    echo "$res"
    exit 1
  fi
else
  exit 0
fi
