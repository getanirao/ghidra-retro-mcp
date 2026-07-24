FROM python:3.11-slim AS builder

ARG GHIDRA_VERSION=11.2
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_20250213.zip

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget unzip openjdk-17-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN wget -q "$GHIDRA_URL" -O ghidra.zip \
    && unzip -q ghidra.zip \
    && rm ghidra.zip \
    && mv ghidra_* ghidra

ENV GHIDRA_INSTALL_DIR=/opt/ghidra
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64

# ── Third-party retro console extension loaders ────────────────────────
RUN mkdir -p /opt/ghidra/Ghidra/Extensions

# gba-ghidra-loader — pre-built .gpa for GBA ROM parsing
RUN wget -q "https://github.com/pudii/gba-ghidra-loader/releases/latest/download/gba-ghidra-loader.gpa" \
    -O /opt/ghidra/Ghidra/Extensions/gba-ghidra-loader.gpa || true

# NTRGhidra — Nintendo DS workspace engine
RUN wget -q "https://github.com/pedro-javierf/NTRGhidra/releases/latest/download/NTRGhidra.zip" \
    -O /opt/ghidra/Ghidra/Extensions/NTRGhidra.zip || true

# Ghidra-Switch-Loader — Switch NSO/NCA/XCI support
RUN wget -q "https://github.com/Adubbz/Ghidra-Switch-Loader/releases/latest/download/Ghidra-Switch-Loader.zip" \
    -O /opt/ghidra/Ghidra/Extensions/Ghidra-Switch-Loader.zip || true

# GhidraNes — NES iNES loader (requires Gradle build if no release asset;
#             install manually from https://github.com/kylewlacy/GhidraNes)

# ghidra_psx_ldr — PlayStation 1 (PSX) executable loader
RUN wget -q "https://github.com/lab313ru/ghidra_psx_ldr/releases/latest/download/ghidra_psx_ldr.zip" \
    -O /opt/ghidra/Ghidra/Extensions/ghidra_psx_ldr.zip || true

# Ghidra-SegaMasterSystem-Loader — SMS / Game Gear support
RUN wget -q "https://github.com/VGKintsugi/Ghidra-SegaMasterSystem-Loader/releases/latest/download/Ghidra-SegaMasterSystem-Loader.zip" \
    -O /opt/ghidra/Ghidra/Extensions/Ghidra-SegaMasterSystem-Loader.zip || true

# Ghidra-SegaSaturn-Loader — Saturn dual-SH2 workspace engine
RUN wget -q "https://github.com/VGKintsugi/Ghidra-SegaSaturn-Loader/releases/latest/download/Ghidra-SegaSaturn-Loader.zip" \
    -O /opt/ghidra/Ghidra/Extensions/Ghidra-SegaSaturn-Loader.zip || true

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir -e .

EXPOSE 0
ENTRYPOINT ["ghidra-bizhawk-mcp"]
