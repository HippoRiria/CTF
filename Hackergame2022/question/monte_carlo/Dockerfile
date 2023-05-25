FROM debian:11
RUN apt update && apt -y upgrade && \
    apt install -y gcc && rm -rf /var/lib/apt/lists/*
COPY monte_carlo.c /
RUN gcc -O3 /monte_carlo.c -o /a.out
CMD ["/a.out"]
