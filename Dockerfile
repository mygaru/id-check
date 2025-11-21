# Build stage (named "builder")
FROM golang:1.23 AS builder
ARG VAULT_URI

ARG APP_NAME=id-check
WORKDIR /usr/src/${APP_NAME}

# Copy the source code and configuration
COPY . .
COPY ./cfg/example.ini /etc/${APP_NAME}/base.ini

RUN mkdir -p /etc/${APP_NAME}/requests

# Build the Go binary
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor \
    -a -installsuffix cgo -o /usr/local/bin/${APP_NAME} ./cmd/${APP_NAME}

# Final stage (production image)
FROM alpine
ARG APP_NAME=id-check

# Copy the binary and configuration from the "builder" stage
COPY --from=builder /usr/local/bin/${APP_NAME} /usr/local/bin/${APP_NAME}
COPY --from=builder /etc/${APP_NAME}/base.ini /etc/${APP_NAME}/base.ini
COPY --from=builder /etc/${APP_NAME}/requests /etc/${APP_NAME}/requests
# Expose ports if necessary
EXPOSE 8090

# Set the command to run the application
CMD ["/usr/local/bin/id-check", "-config", "/etc/id-check/base.ini"]