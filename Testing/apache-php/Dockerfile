FROM php:8.1-apache

# Enable Apache mod_rewrite
RUN a2enmod rewrite

# Install PHP extensions
RUN docker-php-ext-install mysqli pdo pdo_mysql

# Optional: Copy custom php.ini
# COPY php.ini /usr/local/etc/php/

# Set working directory
WORKDIR /var/www/html
