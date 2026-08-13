# Build the React app with Vite. This image is a build artifact carrier, not a server:
# the compose `web` service runs it once, copies /app/dist into the shared `site` volume
# and exits, and the separate `nginx` service serves that volume. Nothing is installed on
# the host - the node toolchain only exists inside this image.
#
# The build runs at image-build time, not container-start time, so restarting the stack
# does not need registry.npmjs.org - but editing web/ does need a rebuild
# (`./setup.sh restart`), because the compiled assets live in this image.

FROM node:20-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --no-audit --no-fund
COPY . .
RUN npm run build
