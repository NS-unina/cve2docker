#!/bin/bash
wp core install --path="/var/www/html" --url=http://localhost --title="test" --admin_user=test --admin_password=test --admin_email=test@test.test
wp theme --path="/var/www/html" activate fruitful
