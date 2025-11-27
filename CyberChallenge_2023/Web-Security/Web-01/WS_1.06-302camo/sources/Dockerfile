FROM php:7.1.8-apache

RUN apt-get update -y && apt-get install git zip sqlite3 libsqlite3-dev -y

# install composer
COPY src/composer.json /srv/app/composer.json
WORKDIR /srv/app
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer \
    && composer install --no-interaction

# Install the db
COPY configs/init.sql /srv/init.sql
RUN sqlite3 /srv/app.db < /srv/init.sql

COPY src /srv/app
COPY configs/apache.conf /etc/apache2/sites-available/000-default.conf
COPY configs/php.ini /etc/php/php.ini
COPY configs/ports.conf /etc/apache2/ports.conf

RUN chown -R www-data:www-data /srv/ \
&& a2enmod rewrite

RUN service apache2 restart
ENV PATH="~/.composer/vendor/bin:./vendor/bin:${PATH}"