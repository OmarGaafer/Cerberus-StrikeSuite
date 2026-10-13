# Nmap Setup, Installation & Testing Guide

Complete guide to install, configure, run, and test the Nmap integration in Cerberus-StrikeSuite.

---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Install Nmap on the Server](#install-nmap-on-the-server)
3. [Install Python Dependencies](#install-python-dependencies)
4. [Configure Database](#configure-database)
5. [Run Migrations](#run-migrations)
6. [Start the Backend](#start-the-backend)
7. [Test Nmap Wrapper (Standalone)](#test-nmap-wrapper-standalone)
8. [Test the API](#test-the-api)
9. [Test Every Nmap Feature](#test-every-nmap-feature)
10. [Troubleshooting](#troubleshooting)

---

## 1. Prerequisites

| Requirement | Minimum | Check command |
| :--- | :--- | :--- |
| Python | 3.10+ | `python3 --version` |
| PostgreSQL | 13+ | `psql --version` |
| Redis | 6+ | `redis-cli --version` |
| Node.js (frontend, optional) | 18+ | `node --version` |
| Git | Any | `git --version` |

**⚠️ Important:** Nmap needs a **real server** (VPS, dedicated, or Docker). Free hosting like Render Free Tier, Railway Free, and Vercel **block raw sockets** and Nmap will not work there.

Recommended providers for Nmap:
- DigitalOcean Droplet ($6/mo)
- Linode / Akamai
- Contabo VPS
- AWS EC2 / GCP Compute
- Docker on any VPS

---

## 2. Install Nmap on the Server

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y nmap ncat ndiff nping
