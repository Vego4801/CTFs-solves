# these two are in common for all the chalenges.
# We need to install some packets in order to "simplify" some challenges
FROM ubuntu:18.04
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y wget curl netcat 

# common for python3 challenges
RUN apt-get install -y python3 python3-pip \
 && pip3 install --no-cache-dir gunicorn \
 && useradd -ms /bin/null web 

COPY requirements.txt /srv/app/
RUN pip3 install --no-cache-dir -r /srv/app/requirements.txt

RUN apt-get install -y nginx supervisor

COPY config/nginx.conf /etc/nginx/nginx.conf
COPY config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY src /srv/app/
COPY src/uwsgi.ini /etc/uwsgi/

ENV UWSGI_INI /srv/app/uwsgi.ini

WORKDIR /srv/app/
