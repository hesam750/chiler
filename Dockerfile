FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --production

COPY . .

ENV PORT=8000 \
    AUTH_SECRET=change-me \
    ADMIN_USER=admin \
    ADMIN_PASS=admin123 \
    USER_USER=user \
    USER_PASS=user123 \
    ALLOWED_PROXY_HOSTS=""

EXPOSE 8000

CMD ["node", "server/index.js"]
