FROM docker.io/library/composer:2@sha256:af98f42dfff7c68ba8d53c2164fd9fde1087b7d449514baa38c418b1f6bc4bac AS dependencies
WORKDIR /plugin
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-interaction --prefer-dist --no-scripts
COPY . .
FROM docker.io/library/matomo:5-apache@sha256:1e00192627025a9eb9108858a0d2fcedb495958adf8ee12cd2b2e4ec306efae4
COPY --from=dependencies /plugin /usr/src/matomo/plugins/Soca
COPY demo/install.php /opt/soca-demo-install.php
COPY demo/apache.conf /etc/apache2/sites-available/000-default.conf
RUN a2enmod ssl rewrite && mkdir -p /run/soca
