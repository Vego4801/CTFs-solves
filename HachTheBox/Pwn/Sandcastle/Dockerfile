FROM ubuntu@sha256:d1e2e92c075e5ca139d51a140fff46f84315c0fdce203eab2807c7e495eff4f9
RUN useradd -m -d /home/ctf ctf
RUN apt update && \
    apt install -y socat strace

RUN echo '#!/bin/sh\necho "HTB{fake_flag_for_testing}"' > /flag-reader && \
    chmod +x /flag-reader

USER ctf
RUN cp $(which date) /home/ctf/date && \
    chown ctf /home/ctf/date && \
    chmod 755 /home/ctf/date
WORKDIR /home/ctf/sandcastle
COPY sandcastle sandcastle

EXPOSE 1337

CMD ["socat", "tcp-l:1337,reuseaddr,fork", "EXEC:/home/ctf/sandcastle/sandcastle"]
