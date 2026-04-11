set dotenv-load := true

default:
    @just --list


export JAVA_HOME := shell('/usr/libexec/java_home', '-v', env("JAVA_VERSION"))
export JC_HOME :=  join(justfile_directory(), 'sdks', env("JC"))

buildApplet:
    @echo "Java Home: ${JAVA_HOME}"
    @echo "JC Home: ${JC_HOME}"
    cd mokapot && ant clean && ant build

testApplet:
    cd mokapot && ant test

buildClient:
    #!/usr/bin/env sh
    cd barista
    echo "Tidy gomod..."
    go mod tidy
    [[ -f barista ]] && rm barista
    [[ -f crema ]] && rm crema
    echo "Building Barista..."
    go build ./cmd/barista
    echo "Building Crema..."
    go build ./cmd/crema

all: buildApplet buildClient
