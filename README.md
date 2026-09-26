# Aperture Relay: Chained Intermediate CTF

Aperture Relay is a three-flag challenge that moves from a web application into evidence analysis and finally a contained Linux host. Each stage supplies information needed for the next.

## Challenge brief

An archive reconciliation incident suggests that a restricted parent record contains unusual survey evidence. Starting with the issued analyst identity, follow the evidence chain and capture all three flags.

The intended path uses:

- web traffic and broken object-level authorization;
- analysis of a PNG evidence file;
- remote access using credentials discovered during the investigation;
- Linux privilege enumeration and escalation.

Do not inspect the container filesystem, Docker volume, database, image layers, or project source while playing. Do not brute-force passwords or network services. Everything required is discoverable through the intended interfaces.

## Start the challenge

Requirements: Docker Engine with the Compose plugin.

For localhost-only access:

```bash
docker compose up --build -d
```

For an isolated lab LAN, bind to the Docker host's lab address:

```bash
BIND_IP=10.10.1.87 docker compose up --build -d
```

Replace `10.10.1.87` with the actual Docker host address. Do not use a public or internet-facing interface.

## Entry point

Web portal:

```text
http://DOCKER_HOST:8080
```

Issued web identity:

```text
Username: analyst
Password: Analyst!2026
```

The SSH service is exposed on TCP port `2222`, but its credentials are part of the challenge and are not supplied here.

## Flags

There are three dynamically generated flags. All use the format:

```text
flag{...}
```

The flags remain stable across ordinary container restarts because challenge state is stored in a named volume.

## Suggested player tools

- Browser developer tools or an intercepting proxy
- `curl`, `file`, `strings`, `exiftool`, and PNG steganography tooling
- `ssh` and standard Linux enumeration commands

## Spoiler-free hints

1. Compare the human-readable incident number with the object identifier used in the detail request.
2. A visible incident names a parent record that is not in the assigned-record list.
3. Evidence can contain information that ordinary image viewers do not display.
4. Once on the Linux host, enumerate delegated privileges before searching the filesystem blindly.

## Operations

Check status and logs:

```bash
docker compose ps
docker compose logs --tail=100 aperture-relay
```

Stop while preserving flags and progress:

```bash
docker compose down
```

Reset everything and generate three new flags and new remote-access credentials:

```bash
docker compose down -v
docker compose up --build -d
```

The solution writeup is maintained separately from this player package.
