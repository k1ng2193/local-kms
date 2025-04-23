FROM golang:1.20-alpine AS build

RUN apk update && apk add git

RUN mkdir -p /go/src/github.com/k1ng2193/local-kms
COPY . /go/src/github.com/k1ng2193/local-kms

WORKDIR /go/src/github.com/k1ng2193/local-kms

RUN go install


# Build the final container with just the resulting binary
FROM alpine

COPY --from=build /go/bin/local-kms /usr/local/bin/local-kms

RUN mkdir /init
RUN mkdir /data

ENV KMS_ACCOUNT_ID 111122223333
ENV KMS_REGION us-east-2
ENV KMS_DATA_PATH /data

ENV PORT 8080

ENTRYPOINT ["local-kms"]
