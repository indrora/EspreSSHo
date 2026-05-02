set dotenv-load := true

_default:
    @just --list


export JAVA_HOME := shell('/usr/libexec/java_home', '-v', env("JAVA_VERSION"))
export JC_HOME :=  join(justfile_directory(), 'sdks', env("JC"))

# Build the applet using Ant
[group("Build")]
buildApplet:
    @echo "Java Home: ${JAVA_HOME}"
    @echo "JC Home: ${JC_HOME}"
    cd mokapot && ant clean && ant build

# Run ant tests on mokapot
[group("Test")]
testApplet:
    cd mokapot && ant test

# Clean build artifacts from the applet and client applications
[group("Maintenance")]
clean:
    cd mokapot && ant clean
    cd barista && [[ -f barista ]] && rm barista
    cd barista && [[ -f crema ]] && rm crema
    [[ -f gp.jar ]] && rm gp.jar


# Build the client applications
[group("Build")]
[script("/usr/bin/env sh")]
buildClient:
    cd barista
    echo "Tidy gomod..."
    go mod tidy
     echo "Building Barista..."
    go build ./bin/barista
    echo "Building Crema..."
    go build ./bin/crema


@_gp:
    @[[ -f gp.jar ]] || wget https://github.com/martinpaljak/GlobalPlatformPro/releases/latest/download/gp.jar


# Install the applet on the card using GlobalPlatformPro
[group("Tools")]
installApplet: _gp buildApplet
    java -jar gp.jar -install mokapot/build/mokapot-release-v1.0.cap

# Initialize an ACOSJ card that has not been initialized yet, using the provided transport key
[group("Tools")]
[arg("transportKey", long="transport-key", short="t")]
[arg("reader", long="reader", short="r")]
init-acosj transportKey reader="-1": _gp 
    #!/usr/bin/env -S uv run --script
    #
    # /// script
    #
    # dependencies = ["pyscard"]
    #
    # ///
    
    print("Hello from Python!")
    print("Initializing card with transport key: {}".format("{{transportKey}}"))
    
    import smartcard
    from smartcard.System import readers
    from smartcard.util import toHexString, toBytes

    # List available readers
    reader = None
    available_readers = readers()
    if(len (available_readers) == 0):
        print("No smart card readers found.")
        exit(1)
    elif(len(available_readers) == 1):
        reader = available_readers[0]
    else:
        if int("{{reader}}") >= len(available_readers):
            print("Invalid reader index. Available readers:")
            for i, r in enumerate(available_readers):
                print("[{}] {}".format(i, r))
            exit(1)
        reader = available_readers[int("{{reader}}")]
    
    if reader is None:
        print("No reader selected.")
        exit(1)
    print("Using reader: {}".format(reader))

    connection = reader.createConnection()
    try:
        connection.connect()
    except Exception as e:
        print("Failed to connect to the card:", e)
        exit(1)
    print("Connected to card.")
    # Send the initialization command with the transport key and new key
    key_bytes = toBytes("{{transportKey}}")

    init_command = toBytes(f"00A40400 {len(key_bytes):x}") + key_bytes
    print("Sending initialization command: {}".format(toHexString(init_command)))
    

    try:
        response, sw1, sw2 = connection.transmit(init_command)
        print("Response: {}, SW1: {:02X}, SW2: {:02X}".format(toHexString(response), sw1, sw2))
        if sw1 == 0x6D and sw2 == 0x00:
            print("Got expected failure.")
        else:
            print("Failed to initialize card. Status: {:02X} {:02X}".format(sw1, sw2))
    except Exception as e:
        print("Error during card initialization:", e)
    
    try:
        response, sw1, sw2 = connection.transmit(toBytes("80d5000000"))
        print("Response: {}, SW1: {:02X}, SW2: {:02X}".format(toHexString(response), sw1, sw2))
    except Exception as e:
        print("Error during card initialization:", e)
    
    print("Done.")