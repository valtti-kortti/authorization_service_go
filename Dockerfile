FROM golang:1.24.3-alpine3.21

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o authorization_service_go .

EXPOSE 3000

CMD ["./authorization_service_go"]