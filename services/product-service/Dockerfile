# [VULN-01] Old base image — node:14 EOL with known CVEs
FROM node:14

# [VULN-02] Runs as root
WORKDIR /app

COPY . .

RUN npm install --production

# [VULN-03] No HEALTHCHECK
EXPOSE 3001

CMD ["node", "src/index.js"]
