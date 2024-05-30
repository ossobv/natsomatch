nats2jetstream-match
====================

Hardcoded matching rules until we want to create those dynamically.

Input:

.. code-block:: json

    {
      "attributes": {
        "filename": "/var/log/nginx/acme.log",
        "host": "lb1.zl.example.com",
        "log.file.name": "acme.log",
        "log.file.path": "/var/log/nginx/acme.log",
        "loki.attribute.labels": "filename",
        "observed_time_unix_nano": 1716901443972772000,
        "section": "acme",
        "tenant": "wilee",
        "time_unix_nano": 1716901443972185600
      },
      "dropped_attributes_count": 0,
      "message": "1.2.3.4 - - [28/May/2024:15:04:03 +0200] \"POST /foo HTTP/2.0\" 200 16 \"-\" \"Mozilla/5.0\"",
      "observed_timestamp": "2024-05-28T13:04:03.972772087Z",
      "source_type": "opentelemetry",
      "timestamp": "2024-05-28T13:04:03.972185559Z"
    }

Output:

.. code-block:: rust

    Match {
        subject: "bulk.nginx.wilee.acme.lb1-zl-example-com"
    }
