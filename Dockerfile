FROM node:20-alpine
RUN apk add --no-cache gnupg tar
WORKDIR /app
COPY package.json .
RUN npm install --production
COPY app.js .
COPY public ./public
EXPOSE 8084
CMD ["node", "app.js"]
