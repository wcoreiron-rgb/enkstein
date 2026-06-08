FROM node:20-alpine AS base
WORKDIR /app
ENV INTERNAL_API_URL=http://backend:8000

# Install dependencies
COPY package.json package-lock.json* ./
RUN npm install --frozen-lockfile 2>/dev/null || npm install

COPY . .

RUN npm run build

EXPOSE 3000

CMD ["npm", "run", "start"]
