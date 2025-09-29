# Use official nginx base image
FROM nginx:stable-alpine

# Expose default nginx port
EXPOSE 80

# Healthcheck (optional but recommended)
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q --spider http://localhost/ || exit 1

# Default command (inherited from base image)

