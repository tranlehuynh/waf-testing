# Build the React app with Vite, then serve the static output with nginx.
# Nothing is installed on the host - the node toolchain only exists in the
# build stage and is discarded.

FROM node:20-alpine AS build
WORKDIR /app
COPY package.json ./
RUN npm install --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
