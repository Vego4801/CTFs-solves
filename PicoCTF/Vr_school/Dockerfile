FROM ubuntu@sha256:2aeed98f2fa91c365730dc5d70d18e95e8d53ad4f1bbf4269c3bb625060383f0 AS chall

RUN apt-get update -y && apt-get install -y --no-install-recommends lib32stdc++6 \
    && rm -rf /var/lib/apt/lists/*

FROM redpwn/jail:sha-a795cdd

COPY --from=chall / /srv
COPY flag.txt /srv/app/flag.txt
COPY chall /srv/app/run
