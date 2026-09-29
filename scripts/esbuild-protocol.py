"""Bounded test codec for the pinned esbuild stdio protocol (no JS execution)."""
import struct

LIMIT = 16 * 1024 * 1024


def encode(value):
    if value is None:
        return b'\0'
    if isinstance(value, bool):
        return b'\1' + bytes([value])
    if isinstance(value, int):
        return b'\2' + struct.pack('<i', value)
    if isinstance(value, (str, bytes)):
        data = value.encode() if isinstance(value, str) else value
        return bytes([3 if isinstance(value, str) else 4]) + struct.pack('<I', len(data)) + data
    if isinstance(value, list):
        return b'\5' + struct.pack('<I', len(value)) + b''.join(map(encode, value))
    if isinstance(value, dict):
        return b'\6' + struct.pack('<I', len(value)) + b''.join(
            struct.pack('<I', len(k.encode())) + k.encode() + encode(v) for k, v in value.items())
    raise ValueError('unsupported protocol value')


def request(value):
    payload = struct.pack('<I', 0) + encode(value)  # request ID 0
    if len(payload) > LIMIT:
        raise ValueError('request too large')
    return struct.pack('<I', len(payload)) + payload


def response(data):
    if len(data) > LIMIT:
        raise ValueError('response too large')
    position = 0

    def take(n):
        nonlocal position
        if n < 0 or position + n > len(data):
            raise ValueError('truncated protocol data')
        result = data[position:position+n]
        position += n
        return result

    def u32():
        return struct.unpack('<I', take(4))[0]

    def blob():
        return take(u32())

    def value(depth=0):
        if depth > 32:
            raise ValueError('protocol nesting limit')
        tag = take(1)[0]
        if tag == 0:
            return None
        if tag == 1:
            v = take(1)[0]
            if v > 1:
                raise ValueError('invalid boolean')
            return bool(v)
        if tag == 2:
            return struct.unpack('<i', take(4))[0]
        if tag in (3, 4):
            b = blob()
            return b.decode() if tag == 3 else b
        if tag in (5, 6):
            count = u32()
            if count > 65536:
                raise ValueError('protocol collection limit')
            if tag == 5:
                return [value(depth+1) for _ in range(count)]
            result = {}
            for _ in range(count):
                key = blob().decode()
                if key in result:
                    raise ValueError('duplicate protocol key')
                result[key] = value(depth+1)
            return result
        raise ValueError('unknown protocol type')

    if blob() != b'0.25.0':
        raise ValueError('wrong esbuild handshake version')
    length = u32()
    if length != len(data) - position or u32() != 1:
        raise ValueError('expected exactly one response for request ID 0')
    result = value()
    if position != len(data) or not isinstance(result, dict):
        raise ValueError('invalid response body')
    return result
