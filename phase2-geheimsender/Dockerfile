# Phase 2 -- Geheimsender (Netzwerk/Krypto)
# Wird als Layer in infra/Dockerfile eingebunden. Eigenständig baubar
# für isolierte Tests dieser Phase.
FROM python:3.12-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*
COPY cipher-tool/cipher_stamp.c /tmp/cipher_stamp.c
RUN gcc -O2 -o /tmp/cipher_stamp /tmp/cipher_stamp.c

FROM python:3.12-slim
RUN mkdir -p /opt/lupin
COPY --from=build /tmp/cipher_stamp /opt/lupin/cipher_stamp
RUN chmod 755 /opt/lupin/cipher_stamp
COPY service/geheimsender.py /opt/lupin/geheimsender.py

ENV CIPHER_TOOL_PATH=/opt/lupin/cipher_stamp
ENV LUPIN_ASSOCIATE_KEY_PATH=/run/secrets/id_lupin_associate

EXPOSE 9001
CMD ["python3", "/opt/lupin/geheimsender.py"]
