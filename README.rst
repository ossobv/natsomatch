nats2jetstream
==============

Take messages from plain NATS subscription and feed them into a
persistent NATS JetStream.

Configuration:

.. code-block:: inifile

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
