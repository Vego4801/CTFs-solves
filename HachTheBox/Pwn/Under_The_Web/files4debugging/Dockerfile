# This SHA corresponds to PHP 8.2-cli (matching your earlier API error)
FROM php@sha256:7bd5ed8988462e39498275924dc5b034fab5b8cd16819d113b311db226486de5

# 1. Stay as root to install tools
RUN apt-get update && apt-get install -y \
    libpng-dev \
    gdb \
    gdbserver \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m www
RUN mkdir /app && chown www:www /app

COPY . /app
RUN chown -R www:www /app
WORKDIR /app

# 2. Rename the flag as you did before
RUN random_value=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32) && \
    hashed_value=$(echo -n $random_value | sha256sum | awk '{print $1}') && \
    mv flag.txt $hashed_value

RUN chmod +x ./start.sh

# 3. Expose the GDBserver port and the Web port
EXPOSE 8000
EXPOSE 1234

# 4. Optional: Keep as root for debugging, or switch to www if you're testing perms
# USER www 

CMD ["./start.sh"]
