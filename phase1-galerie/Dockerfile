# Phase 1 -- Galerie-Website (LFI + Honeypot)
# Wird NICHT einzeln deployt, sondern als Layer in infra/Dockerfile
# (dem Gesamt-Image "dermont-target") eingebunden. Eigenständig baubar
# für isolierte Tests der Phase.
FROM php:8.3-apache

RUN a2enmod rewrite

COPY apache-vhost.conf /etc/apache2/sites-available/000-default.conf
COPY app/ /var/www/html/

RUN chown -R www-data:www-data /var/www/html

EXPOSE 80
