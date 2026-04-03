# [VULN-01] Old base image — node:14 has hundreds of known CVEs (EOL since April 2023)
#            Trivy will flag this immediately
FROM node:14

# [VULN-02] No USER directive — process runs as root inside the container
WORKDIR /app

# [VULN-03] COPY . . before .dockerignore — may include .env files, SSH keys, etc.
COPY . .

RUN npm install --production

# [VULN-04] No HEALTHCHECK — K8s can't detect app-level failures
EXPOSE 3000

CMD ["node", "src/index.js"]
