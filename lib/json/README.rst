nats2jetstream-json
===================

Quicker parsing of JSON which we know to have a specific format.

Input:

.. code-block:: json

    {
      "attributes": {
        "host": "mgmt.example",
        "job": "loki.source.journal.logs_journald_generic",
        "observed_time_unix_nano": 1708101998674019800,
        "section": "section-dmz-cat4",
        "systemd_unit": "session-7889.scope",
        "time_unix_nano": 1708101998323659000
      },
      "dropped_attributes_count": 0,
      "message": <900 bytes>,
      "observed_timestamp": "2024-02-16T16:46:38.674019861Z",
      "source_type": "opentelemetry",
      "timestamp": "2024-02-16T16:46:38.323659Z"
    }

Output:

.. code-block:: rust

    BytesAttributes{
        hostname: b"mgmt.example",
        section: b"section-dmz-cat4",
        timestamp: b"1708101998323659000",
    }

Or, in case ``time_unix_nano`` is not set, ``timestamp:
"2024-02-16T16:46:38.323659Z"``. That case is significantly slower because
after finding ``time_unix_nano``, it would've stopped and beeen done.
