"""Minimal Android binary XML (AXML) encoder.

This is the inverse of :mod:`ghostmobile.axml`. It exists so the test suite
(and anyone who wants a crafted, benign manifest) can produce real binary
AndroidManifest.xml content without shipping a proprietary APK. The encoder
supports the subset of the format that the decoder reads back: a string
pool, a resource-id map for android-namespaced attributes, namespace
chunks, and start/end element chunks with typed attributes.

Only what ghostmobile needs is supported: string, boolean, and integer
attribute values. That is sufficient to express debuggable, allowBackup,
exported, permissions, SDK versions, and cleartext flags.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .axml import (
    RES_STRING_POOL_TYPE,
    RES_XML_END_ELEMENT_TYPE,
    RES_XML_END_NAMESPACE_TYPE,
    RES_XML_RESOURCE_MAP_TYPE,
    RES_XML_START_ELEMENT_TYPE,
    RES_XML_START_NAMESPACE_TYPE,
    RES_XML_TYPE,
    TYPE_INT_BOOLEAN,
    TYPE_INT_DEC,
    TYPE_STRING,
    UTF8_FLAG,
)

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Resource ids for the handful of android-namespaced attributes used in
# crafted manifests. The exact value is not parsed back by our decoder, but a
# real AXML resource map associates each android attribute name with its
# framework resource id, so we provide correct ones for fidelity.
_RES_IDS: dict[str, int] = {
    "versionCode": 0x0101021B,
    "versionName": 0x0101021C,
    "minSdkVersion": 0x0101020C,
    "targetSdkVersion": 0x01010270,
    "name": 0x01010003,
    "debuggable": 0x0101000F,
    "allowBackup": 0x01010280,
    "usesCleartextTraffic": 0x010104CA,
    "exported": 0x01010010,
    "permission": 0x01010006,
    "protectionLevel": 0x01010009,
    "label": 0x01010001,
}


@dataclass
class EncAttr:
    name: str
    value: str | int | bool
    namespace: str = ANDROID_NS
    value_type: int | None = None


@dataclass
class EncElement:
    name: str
    attributes: list[EncAttr] = field(default_factory=list)
    children: list[EncElement] = field(default_factory=list)


class _StringPoolBuilder:
    def __init__(self) -> None:
        self._index: dict[str, int] = {}
        self._strings: list[str] = []

    def intern(self, s: str) -> int:
        if s not in self._index:
            self._index[s] = len(self._strings)
            self._strings.append(s)
        return self._index[s]

    @property
    def strings(self) -> list[str]:
        return list(self._strings)


def _encode_utf8_len(value: int) -> bytes:
    if value > 0x7F:
        return bytes([(value >> 8) | 0x80, value & 0xFF])
    return bytes([value])


def _encode_string_pool(strings: list[str]) -> bytes:
    encoded: list[bytes] = []
    offsets: list[int] = []
    cursor = 0
    for s in strings:
        data = s.encode("utf-8")
        chunk = _encode_utf8_len(len(s)) + _encode_utf8_len(len(data)) + data + b"\x00"
        offsets.append(cursor)
        cursor += len(chunk)
        encoded.append(chunk)

    string_data = b"".join(encoded)
    # Pad string data to a 4-byte boundary.
    pad = (-len(string_data)) % 4
    string_data += b"\x00" * pad

    offsets_blob = struct.pack(f"<{len(offsets)}I", *offsets)
    header_size = 28
    strings_start = header_size + len(offsets_blob)
    chunk_size = strings_start + len(string_data)

    header = struct.pack(
        "<HHIIIIII",
        RES_STRING_POOL_TYPE,
        header_size,
        chunk_size,
        len(strings),
        0,  # style count
        UTF8_FLAG,
        strings_start,
        0,  # styles start
    )
    return header + offsets_blob + string_data


def _encode_resource_map(res_ids: list[int]) -> bytes:
    header_size = 8
    body = struct.pack(f"<{len(res_ids)}I", *res_ids)
    chunk_size = header_size + len(body)
    header = struct.pack("<HHI", RES_XML_RESOURCE_MAP_TYPE, header_size, chunk_size)
    return header + body


def _encode_namespace(chunk_type: int, prefix_idx: int, uri_idx: int) -> bytes:
    header_size = 16
    chunk_size = 24
    header = struct.pack("<HHI", chunk_type, header_size, chunk_size)
    node = struct.pack("<iiii", 0, -1, prefix_idx, uri_idx)
    return header + node


def _value_type_for(attr: EncAttr) -> int:
    if attr.value_type is not None:
        return attr.value_type
    if isinstance(attr.value, bool):
        return TYPE_INT_BOOLEAN
    if isinstance(attr.value, int):
        return TYPE_INT_DEC
    return TYPE_STRING


def _value_data_for(pool: _StringPoolBuilder, attr: EncAttr, vtype: int) -> tuple[int, int]:
    """Return (raw_string_index, data) for an attribute value."""
    if vtype == TYPE_STRING:
        idx = pool.intern(str(attr.value))
        return idx, idx
    if vtype == TYPE_INT_BOOLEAN:
        return -1, (0xFFFFFFFF if attr.value else 0)
    # Integer.
    return -1, int(attr.value) & 0xFFFFFFFF


def _encode_start_element(
    pool: _StringPoolBuilder, ns_uri_idx: int, element: EncElement
) -> bytes:
    name_idx = pool.intern(element.name)
    attr_blobs: list[bytes] = []
    for attr in element.attributes:
        a_ns_idx = ns_uri_idx if attr.namespace == ANDROID_NS else -1
        a_name_idx = pool.intern(attr.name)
        vtype = _value_type_for(attr)
        raw_idx, data = _value_data_for(pool, attr, vtype)
        typed = (vtype << 24) | (0 << 16) | 0x0008  # size 8, res0 0
        attr_blobs.append(struct.pack("<iiiII", a_ns_idx, a_name_idx, raw_idx, typed, data))

    attr_count = len(element.attributes)
    header_size = 16  # 8-byte chunk header + 8-byte node header (line, comment)
    node_header = struct.pack("<ii", 0, -1)  # lineNumber, comment
    elem = struct.pack(
        "<iiHHHHHH",
        -1,  # namespace index
        name_idx,
        20,  # attribute start offset from element-data start
        20,  # attribute size
        attr_count,
        0,  # id index
        0,  # class index
        0,  # style index
    )
    elem += b"".join(attr_blobs)
    chunk_size = header_size + len(elem)
    header = struct.pack("<HHI", RES_XML_START_ELEMENT_TYPE, header_size, chunk_size)
    return header + node_header + elem


def _encode_end_element(pool: _StringPoolBuilder, element: EncElement) -> bytes:
    name_idx = pool.intern(element.name)
    header_size = 16
    chunk_size = 24
    header = struct.pack("<HHI", RES_XML_END_ELEMENT_TYPE, header_size, chunk_size)
    body = struct.pack("<iiii", 0, -1, -1, name_idx)
    return header + body


def encode(root: EncElement) -> bytes:
    """Encode an element tree into Android binary XML bytes."""
    pool = _StringPoolBuilder()

    # The android namespace strings should exist in the pool. Resource-map
    # attribute names must be the first entries (index aligned with res map).
    res_names = list(_RES_IDS.keys())
    for n in res_names:
        pool.intern(n)
    res_ids = [_RES_IDS[n] for n in res_names]

    prefix_idx = pool.intern("android")
    ns_uri_idx = pool.intern(ANDROID_NS)

    # Pre-intern element and attribute names/values by doing a dry encode pass.
    body_chunks: list[bytes] = []

    def walk(el: EncElement) -> None:
        body_chunks.append(_encode_start_element(pool, ns_uri_idx, el))
        for child in el.children:
            walk(child)
        body_chunks.append(_encode_end_element(pool, el))

    walk(root)

    # Now the string pool is final. Rebuild element chunks so string indices
    # are consistent (interning is stable, so a second walk yields identical
    # bytes; we rebuild to be safe against ordering).
    body_chunks = []
    walk(root)

    string_pool = _encode_string_pool(pool.strings)
    resource_map = _encode_resource_map(res_ids)
    start_ns = _encode_namespace(RES_XML_START_NAMESPACE_TYPE, prefix_idx, ns_uri_idx)
    end_ns = _encode_namespace(RES_XML_END_NAMESPACE_TYPE, prefix_idx, ns_uri_idx)

    payload = string_pool + resource_map + start_ns + b"".join(body_chunks) + end_ns
    file_size = 8 + len(payload)
    header = struct.pack("<HHI", RES_XML_TYPE, 8, file_size)
    return header + payload
