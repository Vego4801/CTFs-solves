FROM ubuntu:22.04
EXPOSE 1337
# RUN apt update && apt install -y gdbserver    # Uncomment to add gdbserver
RUN groupadd ctf && useradd -m -g ctf ctf
COPY challenge/ /home/ctf/
RUN chown ctf:ctf /home/ctf/users.keys

WORKDIR /home/ctf
USER ctf
CMD ["./khp_server", "-p", "1337"]
CMD ["sh", "-c", "gdbserver 0.0.0.0:4444 ./khp_server -p 1337"]     # Uncomment to run gdbserver

