FROM ghcr.io/madrhacks/jail:latest

COPY --from=openjdk@sha256:6766e11d784d2e02babd76e6520f41facbd25d3015e482af72588bc6f44cb136 / /srv

WORKDIR /srv/app
COPY Chall.jar libcoffeemachine.so menu.txt run ./

ENV FLAG_PATH=/app/flag.txt JAIL_MEM=50M JAIL_PIDS=50 TIMEOUT=30 ENV_LD_LIBRARY_PATH=/usr/java/openjdk-22/lib/
