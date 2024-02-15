nats2jetstream
==============

Take messages from plain NATS subscription and feed them into a
persistent NATS JetStream.

----
TODO
----


☐  Check and fix behaviour on NATS/subscription disconnect/error.

☐  Check and fix behaviour on NATS/JetStream disconnect/error.

☐  Create systemd unitfile or K8S image for continuous running.

☐  Check and configure output JetStream parameters:

- ``{"max_bytes": -1, "max_messages": -1, "discard": "Old", "max_age": 0, "max_message_size": -1, "no_ack": false}``
- See more here: https://docs.nats.io/nats-concepts/jetstream/streams

☐  Discuss whether we want to do anything with JetStream subjects at this point. Makes sense to populate with sections maybe.

☐  Consider whether we want to do any parsing so we can do filtering or better subject setting.

☐  Naming:

- input subject suggestion: "NS.log.vector-in"
- jetstream name suggestion: "bulk"
- jetstream subjects suggestion: "bulk.section.{section}"


-------------------
Configuration/setup
-------------------

Configuration for the Rust version:

.. code-block:: toml

    [input.my_nats]
    # Input source
    nats.server = 'tls://10.20.30.40:4222'
    nats.subject = 'NS.log.vector-in'
    # Server certificate validation (tls.server_name is not working)
    tls.server_name = 'nats.local'
    tls.ca_file = './nats_ca.crt'
    # Client certificate
    tls.cert_file = './nats_client.crt'
    tls.key_file = './nats_client.key'

    [sink.my_jetstream]
    # Output target
    jetstream.server = 'tls://nats.example.com:4222'
    jetstream.name = 'bulk'
    jetstream.subject_tpl = 'bulk.section.{section}'
    # Server certificate validation (tls.server_name is not working)
    tls.ca_file = '/etc/ssl/certs/ca-certificates.crt'
    # Client certificate
    tls.cert_file = './nats_client.crt'
    tls.key_file = './nats_client.key'

Configuration for the Python PoC:

.. code-block:: ini

    [input:my_nats]
    ; Input source
    nats.server = tls://10.20.30.40:4222
    nats.subject = default.nats.vector
    ; Server certificate validation
    tls.server_name = nats.local
    tls.ca_file = ./nats_ca.crt
    ; Client certificate
    tls.cert_file = ./nats_client.crt
    tls.key_file = ./nats_client.key

    [sink:my_jetstream]
    ; Output target
    jetstream.server = tls://nats.example.com:4222
    jetstream.name = teststream
    jetstream.subjects = default.nats.example
    ; Server certificate validation
    tls.ca_file = /etc/ssl/certs/ca-certificates.crt
    ; Client certificate
    tls.cert_file = ./nats_client.crt
    tls.key_file = ./nats_client.key


-----------------------
Binary version and SBOM
-----------------------

The ``git describe`` version is stored and shown on bad arguments:

.. code-block:: console

    $ ./target/release/nats2jetstream -v
    nats2jetstream v0.1.0
    Usage: ./target/release/nats2jetstream -c <config-file>

The built binary (if built using ``cargo auditable build``) includes a
*Software Bill of Materials* (SBOM):

.. code-block:: console

    $ objcopy --dump-section .dep-v0=/dev/stdout target/release/nats2jetstream |
        python3 -c 'import zlib,sys;print(zlib.decompress(sys.stdin.buffer.read()).decode("utf-8"))' |
        jq .
    {
      "packages": [
        {
          "name": "aho-corasick",
          "version": "1.1.2",
          "source": "crates.io",
          "dependencies": [
            45
          ]
        },
        {
          "name": "async-nats",
          "version": "0.33.0",
          "source": "crates.io",
          "dependencies": [
            3,
    ...
