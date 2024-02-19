#!/usr/bin/env python3
"""
nats2jetstream - subscribe to NATS subject, write to NATS JetStream

Configuration, as nats2jetstream.ini::

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
"""
import asyncio
import sys

from argparse import ArgumentParser
from collections import namedtuple
from configparser import DEFAULTSECT, ConfigParser, ExtendedInterpolation
from os import close, environ, fork, kill, pipe, read, waitpid, write, _exit
from signal import SIGALRM, SIGQUIT, alarm, signal
from ssl import Purpose, create_default_context
from time import time
from unittest import TestCase, main as test_main

from nats.aio.client import Client as NATS


global_pids = ()
global_stats = None


class ConfigError(ValueError):
    pass


class StopError(ValueError):
    pass


class Stats:
    def __init__(self, name):
        self.name = name
        self.t0 = time()
        self.count = 0
        self.duration = 0.0

    def inc(self, tm):
        self.duration += tm
        self.count += 1

    def reset(self):
        self.t0 = time()
        self.count = 0
        self.duration = 0.0

    def __repr__(self):
        name = self.name
        msgs = self.count
        msg_per_sec = msgs / (time() - self.t0)
        if self.count:
            ms_per_msg = (self.duration * 1_000 / self.count)
        else:
            ms_per_msg = 0.0
        return (
            f'<Stats: {name} {msgs} msgs '
            f'({msg_per_sec:.3f} msg/s, {ms_per_msg:.3f} ms/msg)>')

    def __str__(self):
        return repr(self)


class IniConfigParser(ConfigParser):
    def __init__(self):
        super().__init__(
            allow_no_value=False,
            delimiters=('=',),
            comment_prefixes=('#', ';'),
            inline_comment_prefixes=('#', ';'),
            strict=True,
            empty_lines_in_values=True,
            default_section=DEFAULTSECT,
            interpolation=ExtendedInterpolation(),  # allows ${variable}
            converters={})


class AppConfig(namedtuple('AppConfig', 'inputs sinks')):
    @classmethod
    def from_configparser(cls, cp):
        inconfs = []
        skconfs = []

        for section_name in cp.sections():
            section = cp[section_name]

            if section_name.startswith('input:'):
                inconfs.append(InputConf.from_section(section))
            elif section_name.startswith('sink:'):
                skconfs.append(SinkConf.from_section(section))
            else:
                raise ConfigError(f'unknown section [{section_name}]')

        if len(inconfs) != 1:
            raise ConfigError('expected exactly one input config')
        if len(skconfs) != 1:
            raise ConfigError('expected exactly one sink config')

        return cls(inputs=tuple(inconfs), sinks=tuple(skconfs))


class FromSectionMixin:
    @classmethod
    def from_section(cls, section):
        # Set None as default for all fields. Set section.
        items = dict((key, None) for key in cls._fields)
        items['section'] = section.name

        # Translate 'tls.ca_file' to 'tls__ca_file' and check for duplicates.
        for key, value in section.items():
            new_key = key.replace('.', '__')
            if new_key not in items:
                raise ConfigError(f'{key} in [{section.name}] unexpected')
            if items[new_key] is not None:
                raise ConfigError(f'{key} in [{section.name}] specified twice')
            items[new_key] = value

        return cls(**items)

    @classmethod
    def _as_array(cls, kwargs, key):
        # NOTE: Must be tuple, not list. Otherwise we have incomparable
        # (contract violating) namedtuples.
        kwargs[key] = tuple(s.strip() for s in kwargs[key].split(','))
        if len(kwargs[key]) != 1:
            raise ConfigError(
                f"[{kwargs['section']}] supports exactly one "
                f"value only for now")


class InputConf(FromSectionMixin, namedtuple(
        'InputConf', (
            'section '
            'nats__server nats__subject '
            'tls__server_name tls__ca_file tls__cert_file tls__key_file'))):
    def __new__(cls, *args, **kwargs):
        cls._as_array(kwargs, 'nats__server')
        return super().__new__(cls, *args, **kwargs)


class SinkConf(FromSectionMixin, namedtuple(
        'SinkConf', (
            'section '
            'jetstream__server jetstream__name jetstream__subjects '
            'tls__server_name tls__ca_file tls__cert_file tls__key_file'))):
    def __new__(cls, *args, **kwargs):
        cls._as_array(kwargs, 'jetstream__server')
        cls._as_array(kwargs, 'jetstream__subjects')
        return super().__new__(cls, *args, **kwargs)


class InputConfTestCase(TestCase):
    def test_all(self):
        cp = IniConfigParser()
        cp.read_string('''\
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
        ''')
        inconf = InputConf.from_section(cp['input:my_nats'])
        self.assertEqual(inconf, InputConf(
            section='input:my_nats',
            nats__server='tls://10.20.30.40:4222',
            nats__subject='default.nats.vector',
            tls__server_name='nats.local',
            tls__ca_file='./nats_ca.crt',
            tls__cert_file='./nats_client.crt',
            tls__key_file='./nats_client.key'))


class SinkConfTestCase(TestCase):
    def test_all(self):
        cp = IniConfigParser()
        cp.read_string('''\
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
        ''')
        skconf = SinkConf.from_section(cp['sink:my_jetstream'])
        self.assertEqual(skconf, SinkConf(
            section='sink:my_jetstream',
            jetstream__server='tls://nats.example.com:4222',
            jetstream__name='teststream',
            jetstream__subjects='default.nats.example',
            tls__server_name=None,
            tls__ca_file='/etc/ssl/certs/ca-certificates.crt',
            tls__cert_file='./nats_client.crt',
            tls__key_file='./nats_client.key'))


async def nats_connect(servers, conf):
    context = create_default_context(purpose=Purpose.SERVER_AUTH)
    try:
        context.load_verify_locations(conf.tls__ca_file)
    except Exception as e:
        raise ConfigError(
            f'error reading CA file {conf.tls__ca_file}') from e
    try:
        context.load_cert_chain(
            certfile=conf.tls__cert_file, keyfile=conf.tls__key_file)
    except Exception as e:
        raise ConfigError(
            f'error reading client cert/key file {conf.tls__cert_file} '
            f'of {conf.tls__key_file}') from e

    nc = NATS()
    await nc.connect(
        servers=list(servers), tls=context,
        tls_hostname=conf.tls__server_name)
    return nc


async def run_input_nats(conf, dst_fd):
    "Consumes NATS, pushes cloud events to pipe"
    global global_stats

    stats = Stats('run_input_nats')

    # Term handler.
    global_stats = stats
    signal(SIGQUIT, handle_child_status)

    try:
        await _run_input_nats(conf, dst_fd, stats)
    except (Exception, KeyboardInterrupt, SystemExit) as e:
        print(
            f'error: run_input_nats: {e} ({e.__class__.__name__}): {stats}',
            file=sys.stderr)
        return 2
    print(f'exit: run_input_nats: {stats}', file=sys.stderr)
    return 0


async def _run_input_nats(conf, dst_fd, stats):
    nc = await nats_connect(conf.nats__server, conf)
    sub = await nc.subscribe(conf.nats__subject)
    try:
        async for msg in sub.messages:
            assert sub.subject == conf.nats__subject, sub.subject

            # This is CloudEvent message data. In json bytestring form.
            # Prepend big endian message size.
            structured_body = msg.data
            sblen = len(structured_body)  # FIXME? handle 64+k?
            assert sblen < 65536, (sblen, structured_body[0:512])
            structured_body = (
                bytes([sblen >> 8, sblen & 0xff]) + structured_body)

            # Write message with length prepended.
            sblen += 2
            t0 = time()
            outlen = write(dst_fd, structured_body)
            stats.inc(time() - t0)  # one message, time to write to pipe
            assert outlen == sblen, (sblen, outlen)
    finally:
        await nc.drain()


async def run_sink_jetstream(conf, src_fd):
    "Consumes NATS, pushes cloud events to pipe"
    global global_stats

    stats = Stats('run_sink_jetstream')

    # Term handler.
    global_stats = stats
    signal(SIGQUIT, handle_child_status)

    try:
        await _run_sink_jetstream(conf, src_fd, stats)
    except (Exception, KeyboardInterrupt, SystemExit) as e:
        print(
            f'error: run_sink_jetstream: {e} ({e.__class__.__name__}): '
            f'{stats}',
            file=sys.stderr)
        return 2
    print(f'exit: run_sink_jetstream: {stats}', file=sys.stderr)
    return 0


async def _run_sink_jetstream(conf, src_fd, stats):
    headers = {'content-type': 'application/cloudevents+json'}

    nc = await nats_connect(conf.jetstream__server, conf)
    js = nc.jetstream()
    await js.add_stream(
        name=conf.jetstream__name, subjects=conf.jetstream__subjects)
    try:
        while True:
            # Read message from other end of the pipe.
            sblen = read(src_fd, 2)
            if not sblen:  # closed pipe
                break

            assert len(sblen) == 2, sblen
            sblen = sblen[0] << 8 | sblen[1]
            structured_body = read(src_fd, sblen)
            inlen = len(structured_body)
            assert inlen == sblen, (sblen, inlen)

            try:
                t0 = time()
                resp = await js.publish(
                    conf.jetstream__subjects[0],
                    structured_body, headers=headers)
                stats.inc(time() - t0)  # one message, time for jetstream pub
                if 0:
                    resp
            except Exception:
                # If this fails, we have:
                # - an unsent structured_body
                # - a bunch of messages still in the pipe
                # We should do something to preserve both, and reconnect.
                raise
    finally:
        await nc.drain()


def handle_child_status(signum, frame):
    global global_stats

    print(f'nats2jetstream: {global_stats}', file=sys.stderr)
    global_stats.reset()


def handle_status(signum, frame):
    global global_pids

    for pid in global_pids:
        try:
            kill(pid, SIGQUIT)
        except OSError:
            pass

    alarm(10)  # re-arm


def main():
    global global_pids

    parser = ArgumentParser()
    parser.add_argument('-c', '--config', help='configuration inifile')
    args = parser.parse_args()

    cp = IniConfigParser()
    try:
        files = cp.read([args.config])
        if files != [args.config]:
            raise ConfigError(f'read error when reading {args.config!r}')
        appconfig = AppConfig.from_configparser(cp)
    except ConfigError as e:
        parser.error(str(e))

    # Create two streams: input and sink.
    rpipe, wpipe = pipe()

    consumer_pid = fork()
    if consumer_pid == 0:
        # Consumer child (us -> sink).
        close(wpipe)
        try:
            status = asyncio.run(run_sink_jetstream(appconfig.sinks[0], rpipe))
        except (Exception, KeyboardInterrupt, SystemExit) as e:
            status = 3
            print(
                f'error: <consumer>: {e} ({e.__class__.__name__})',
                file=sys.stderr)
        close(rpipe)
        sys.stderr.flush()
        sys.stdout.flush()
        _exit(status)

    producer_pid = fork()
    if producer_pid == 0:
        # Producer child (input -> us).
        close(rpipe)
        try:
            status = asyncio.run(run_input_nats(appconfig.inputs[0], wpipe))
        except (Exception, KeyboardInterrupt, SystemExit) as e:
            status = 3
            print(
                f'error: <producer>: {e} ({e.__class__.__name__})',
                file=sys.stderr)
        close(wpipe)
        sys.stderr.flush()
        sys.stdout.flush()
        _exit(status)

    # Not doing anything in parent.
    close(wpipe)
    close(rpipe)

    # Term handler.
    global_pids = (consumer_pid, producer_pid)
    signal(SIGALRM, handle_status)
    signal(SIGQUIT, handle_status)
    alarm(10)

    print(f'nats2jetstream (pids=[{producer_pid} -> {consumer_pid}])')
    try:
        # Here we just wait for either to die and then kill the other
        # gracefully.
        first_pid, first_child_status = waitpid(-1, 0)
    except (Exception, KeyboardInterrupt, SystemExit) as e:
        print(
            f'error: nats2jetstream: {e} ({e.__class__.__name__})',
            file=sys.stderr)
        handle_status(0, None)
        kill(producer_pid, 2)
        first_pid, first_child_status = waitpid(-1, 0)

    if first_pid == producer_pid:
        # This is the easy case. The consumer can keep consuming until EOF and
        # then we're done.
        producer_status = first_child_status
        second_pid, consumer_status = waitpid(-1, 0)
        assert second_pid == consumer_pid, (consumer_pid, second_pid)
        producer_died_first = True
    else:
        # This is harder. Now we have to (a) notify the producer to stop and
        # (b) we have to keep the consumed records. We do not like this case.
        consumer_status = first_child_status
        kill(producer_pid, 2)  # FIXME: gracefully?
        second_pid, producer_status = waitpid(-1, 0)
        assert second_pid == producer_pid, (producer_pid, second_pid)
        producer_died_first = False

    # ...
    print(
        'EOF',
        ('producer_died' if producer_died_first else 'consumer_died'),
        consumer_status, producer_status, file=sys.stderr)


if __name__ == '__main__':
    if environ.get('RUNTESTS', '') not in ('', '0'):
        test_main()

    main()
