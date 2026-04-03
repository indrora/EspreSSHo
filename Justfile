default:
    @just --list


# Both env vars are required:
#   JAVA_HOME — must point to Java 21 LTS
#   JC_HOME   — must point to JavaCard SDK 3.2.0v25.1 (newer converter supports ARM64)
JAVA_HOME := env("JAVA_HOME")
JC_HOME   := env("JC_HOME")

buildApplet:
    cd mokapot && ant clean && ant build

testApplet:
    cd mokapot && ant test

buildClient:
    cd barista && go build .

all: buildApplet buildClient
