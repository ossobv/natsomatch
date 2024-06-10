natsomatch (NATS o' Match)
==========================

Take *Grafana/Vector* passed log messages from *NATS JetStream*, match
category and create new subjects.

* Setup HOWTO:

  - Make sure there is a JetStream stream to read from. Creating a
    stream with a subjects set to the Vector subject will make it
    collect the published message automatically::

      nats stream add --subjects=default.nats.vector \
        --description='All messages from vector' \
        --storage=file --replicas=3 \
        --retention=limits --discard=old --max-bytes=20GiB --max-msgs=-1 \
        --max-msgs-per-subject=-1 --max-age=-1 --max-msg-size=-1 \
        --dupe-window=60s --no-allow-rollup --no-deny-delete \
        --no-deny-purge --allow-direct bulk_unfiltered

  - Create a consumer which we'll use to read from::

      nats consumer add --pull --deliver=all --ack=explicit \
        --replay=instant --filter= --max-deliver=-1 --max-pending=0 \
        --no-headers-only --backoff=none \
        bulk_unfiltered bulk_unfiltered_consumer

  - Create a bunch of streams to write to, one for every possible
    matched subject. Also create a consumer for test purposes while
    we're at it::

      MATCHES=$(cat lib/match/src/log_matcher.rs |
                grep -FA2 'Ok(Match' |
                sed -e '/subject: /!d;s/.*format!("bulk[.]//;s/[.].*//' |
                sort)

      for match in $MATCHES; do

        nats stream add --subjects="bulk.$tp.>" --description="Bulk $match" \
          --storage=file --replicas=3 --retention=limits --discard=old \
          --max-bytes=2GiB --max-msgs=-1 --max-msgs-per-subject=-1 \
          --max-age=-1 --max-msg-size=-1 --dupe-window=60s --no-allow-rollup \
          --no-deny-delete --no-deny-purge --allow-direct "bulk_match_${match}"

        nats consumer add --pull --deliver=all --ack=explicit \
          --replay=instant --filter= --max-deliver=-1 --max-pending=0 \
          --no-headers-only --backoff=none \
          "bulk_match_${match}" "bulk_match_${match}_consumer"

      done

* Next, we'll need a couple of these running. Could be more or less
  depending on how fast consumption rates are. In ``doc/`` there's a
  *Kubernetes* setup.

* Configuration can be seen below. If you're using *Kubernetes*,
  configure it in the *ConfigMap*.

* The ``/healthz`` health check and stats reporting is listening on port 3000.
  The *Kubernetes* container uses this to check liveness.


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


----
TODO
----

☐  Clear (greppable) log message on startup. Clear log message on shutdown.

☐  Hardcoded attributes are now in lib/json/src/payload_parser.rs. Maybe make them configurable.

☐  Hardcoded matching rules are now in lib/match/src/log_matcher.rs. Maybe make them configurable.

☐  See if we can add filters to remove useless messages. We'll want to check some live data here.

☐  Add configurable bind address for /healthz server. Use a ping/pong test on input/sink too?

☐  See if we want to rely on ghcr.io/rust-cross/rust-musl-cross ( https://github.com/rust-cross/rust-musl-cross ) or want to build something from the official images.

☐  See if we want to use cargo-chef for docker layer caching (speeding up release builds).

☐  Stats improvements:

- Count average message length.
- Report stats on output subscriptions (streams) so we can reorder filters for more speed.

☐  Monitoring improvements:

- Right now we have no easy detection of streams that are not handled quickly enough. Maybe check bulk_unfiltered_consumer for "unprocessed" counts.

☐  Check and fix behaviour on NATS/JetStream disconnect/error. Consider auto-creating streams. (Where are the settings?)


-----------------------
Binary version and SBOM
-----------------------

The ``git describe`` version is stored and shown on bad arguments:

.. code-block:: console

    $ ./target/release/natsomatch -v
    natsomatch v0.1.0
    Usage: ./target/release/natsomatch -c <config-file>

The built binary (if built using ``cargo auditable build``) includes a
*Software Bill of Materials* (SBOM):

.. code-block:: console

    $ objcopy --dump-section .dep-v0=/dev/stdout target/release/natsomatch |
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
