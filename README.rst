nats2jetstream
==============

Take messages from plain NATS subscription and feed them into a
persistent NATS JetStream.

----
TODO
----

☐  Add JetStream target/sink configuration?

- We probably want: replicas 3.
- Maybe: allow-direct.
- ``{"max_bytes": -1, "max_messages": -1, "discard": "Old", "max_age": 0, "max_message_size": -1, "no_ack": false}``
- See more here: https://docs.nats.io/nats-concepts/jetstream/streams

☐  Add configurable bind address for /healthz server. Use a ping/pong test on input/sink too?

☐  See if we want to rely on ghcr.io/rust-cross/rust-musl-cross ( https://github.com/rust-cross/rust-musl-cross ) or want to build something from the official images.

☐  Small stuff:

- Log/info when starting.
- Log/info when stopping.
- Add a buffer for unique-ids so we can detect and error if were generating dupe unique ids.

☐  Check and fix behaviour on NATS/subscription disconnect/error.

☐  Check and fix behaviour on NATS/JetStream disconnect/error.

☐  Consider whether we want to do any parsing so we can do filtering or better subject setting.

- right now we parse the ``"section"`` from the attributes and can place that in the subject ``{section}``.



-------------------
Configuration/setup
-------------------

Configuration for the Rust version:

.. code-block:: toml

    [input.my_nats]
    # Input source
    nats.server = 'nats://10.20.30.40:4222'
    nats.subject = 'NS.log.vector-in'
    # Server certificate validation (tls.server_name is not working)
    tls.server_name = 'nats.local'
    tls.ca_file = './nats_ca.crt'
    # Client certificate
    tls.cert_file = './nats_client.crt'
    tls.key_file = './nats_client.key'

    [sink.my_jetstream]
    # Output target
    jetstream.server = 'nats://nats.example.com:4222'
    jetstream.name = 'bulk'
    jetstream.subject_tpl = 'bulk.section.{section}'
    # Server certificate validation (tls.server_name is not working)
    tls.ca_file = '/etc/ssl/certs/ca-certificates.crt'
    # Client certificate
    tls.cert_file = './nats_client.crt'
    tls.key_file = './nats_client.key'


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
