FROM debian:bullseye-slim

# deps
RUN sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list && \
    apt update && apt -y upgrade && \
    apt install --no-install-recommends -y texlive-latex-base texlive-latex-extra texlive-extra-utils ghostscript poppler-utils pnmtopng graphicsmagick-imagemagick-compat python3 && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir /app

COPY server.py /app/
COPY latex_to_image_converter.sh /app/
COPY base.tex /app/

CMD ["python3", "/app/server.py"]
