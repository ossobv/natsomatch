nats2jetstream
==============

Take messages from plain *NATS* subscription and feed them into a
persistent *NATS JetStream*.

* Setup HOWTO:

  - Make sure there is a JetStream stream to read from. If the data is
    published without a JetStream, create one automatically::

      nats stream add --subjects=default.nats.vector \
        --description='All messages from vector' \
        --storage=file --replicas=3 \
        --retention=limits --discard=old --max-bytes=20GiB --max-msgs=-1 \
        --max-msgs-per-subject=-1 --max-age=-1 --max-msg-size=-1 \
        --dupe-window=60s --no-allow-rollup --no-deny-delete \
        --no-deny-purge --allow-direct bulk_by_section

  - Skip the rest below. We don't need to do anything. The above line already
    takes care of the original goal of this project.

  - Next, we need a project that does filtering and rewriting into
    different streams/subjects.

  - Create a consumer, manually::

      nats consumer add --pull --deliver=all --ack=explicit \
        --replay=instant --filter= --max-deliver=-1 --max-pending=0 \
        --no-headers-only --backoff=none \
        bulk_unfiltered bulk_unfiltered_consumer

* Various subjects may have been configured in lib/src/log_matcher.rs. We'll
  need to create streams for those::

    for tp in haproxy nginx k8s unknown; do
        nats stream add --subjects="bulk.$tp.*" --description="Bulk $tp" \
          --storage=file --replicas=3 --retention=limits --discard=old \
          --max-bytes=2GiB --max-msgs=-1 --max-msgs-per-subject=-1 \
          --max-age=-1 --max-msg-size=-1 --dupe-window=60s --no-allow-rollup \
          --no-deny-delete --no-deny-purge --allow-direct bulk_$tp
    done


----
TODO
----

☐  Rename project from nats2jetstream to nats-o-match.

☐  Hardcoded attributes are now in lib/json/src/payload_parser.rs. Maybe make them configurable.

☐  Hardcoded matching rules are now in lib/match/src/log_matcher.rs. Maybe make them configurable.

☐  Explain setup:

- one or more pods
- configuration as toml seen below
- manual Sink setup using nats cli ...
- explain that tls.server_name is not working right now
- explain how to check healthz and on which port it's listening

☐  Log startup.

☐  Log shutdown.

☐  See if we can add filters to remove useless messages. We'll want to check some live data here.

☐  Add configurable bind address for /healthz server. Use a ping/pong test on input/sink too?

☐  See if we want to rely on ghcr.io/rust-cross/rust-musl-cross ( https://github.com/rust-cross/rust-musl-cross ) or want to build something from the official images.

☐  Small stuff:

- Also count average message length.

☐  Check and fix behaviour on NATS/subscription disconnect/error.

☐  Check and fix behaviour on NATS/JetStream disconnect/error.


-------------------
Configuration/setup
-------------------

Configuration for the Rust version:

.. code-block:: toml

    [input]
    # Input source
    nats.server = 'nats://10.20.30.40:4222'
    # Server certificate validation (tls.server_name is not working)
    tls.server_name = 'nats.local'
    tls.ca_file = './nats_ca.crt'
    # Client certificate
    tls.cert_file = './nats_client.crt'
    tls.key_file = './nats_client.key'
    # Select manually made consumer from stream
    nats.stream = 'bulk_unfiltered'
    nats.consumer = 'bulk_unfiltered_consumer'

    [sink]
    # Output target
    nats.server = 'nats://nats.example.com:4222'
    nats.auth = { username = 'derek', password = 's3cr3t!' }
    # Server certificate validation (tls.server_name is not working)
    tls.ca_file = '/etc/ssl/certs/ca-certificates.crt'
    # Client certificate
    #tls.cert_file = './nats_client.crt'
    #tls.key_file = './nats_client.key'
    # No need to set jetstream name or subjects. The subject generation is
    # hardcoded for now, based on the message.


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


-----------
Rust idioms
-----------

* ``String vs. Box<str>``: don't use ``Box<str>`` to make the string
  immutable or try to save a uint. Only use it if you have many many strings.
  (Similarly: see ``Box<[T]>`` vs. ``Vec<T>``.)

* ``into/to_string/to_owned``: ``to_string`` is to get a human
  representation of something; ``to_owned`` is for converting a
  ``&String`` (or maybe a ``&str``) to a copy/clone; ``into`` is for
  conversion (``String`` to ``PathBuf``, ``&str`` to ``String``).
