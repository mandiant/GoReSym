#!/bin/bash
trap "exit" INT
sudo rm -rf $(pwd)/test
versions=("1.17" "1.16" "1.15" "1.14" "1.13" "1.12" "1.11" "1.10" "1.9" "1.8" "1.7" "1.6" "1.5")
for v in "${versions[@]}"
do
    GO_TAG=$v
    GO_VER=$(echo "$GO_TAG" | tr -d '.')
    
    rm Dockerfile.test
cat <<EOF >Dockerfile.test
    FROM golang:$GO_TAG-alpine
    ARG ver=$GO_VER
    ENV ver \${ver}
    
    WORKDIR \$ver/src/testproject
    COPY ./testproject ./
    RUN apk update && apk add --no-cache git
    CMD mkdir -p /tmp/output/build/\$ver/ && export GOARCH=amd64 \
        && export GOOS=linux && go build ./ && mv testproject /tmp/output/build/\$ver/testproject_lin && go build -ldflags="-s -w" ./ && mv testproject /tmp/output/build/\$ver/testproject_lin_stripped \
        && export GOOS=windows && go build ./ && mv testproject.exe /tmp/output/build/\$ver/testproject_win.exe && go build -ldflags="-s -w" ./ && mv testproject.exe /tmp/output/build/\$ver/testproject_win_stripped.exe \
        && export GOOS=darwin && go build ./ && mv testproject /tmp/output/build/\$ver/testproject_mac && go build -ldflags="-s -w" ./ && mv testproject /tmp/output/build/\$ver/testproject_mac_stripped \
        && export GOARCH=386 \
        && export GOOS=linux && go build ./ && mv testproject /tmp/output/build/\$ver/testproject_lin_32 && go build -ldflags="-s -w" ./ && mv testproject /tmp/output/build/\$ver/testproject_lin_stripped_32 \
        && export GOOS=windows && go build ./ && mv testproject.exe /tmp/output/build/\$ver/testproject_win_32.exe && go build -ldflags="-s -w" ./ && mv testproject.exe /tmp/output/build/\$ver/testproject_win_stripped_32.exe \
        && export GOOS=darwin && go build ./ && mv testproject /tmp/output/build/\$ver/testproject_mac_32 && go build -ldflags="-s -w" ./ && mv testproject /tmp/output/build/\$ver/testproject_mac_stripped_32
EOF
    docker build -f Dockerfile.test . -t goresym_testproject
    docker run -v $(pwd)/test:/tmp/output/ goresym_testproject
done

rm Dockerfile.test

