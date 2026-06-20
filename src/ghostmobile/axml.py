"""Compact decoder for Android binary XML (AXML).

Android stores AndroidManifest.xml (and other XML resources) in a binary
chunk format rather than plain text. This module implements a small,
dependency-free decoder that walks the chunk stream and reconstructs the
element tree: element names, attributes, and their resolved values.

Reference: the AXML/ARSC chunk format used by aapt. We parse the string
pool, the optional resource-id map, and the XML node chunks. This is enough
to recover everything ghostmobile's Android checks need from the manifest.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

# Chunk type identifiers.
RES_XML_TYPE = 0x0003
RES_STRING_POOL_TYPE = 0x0001
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104

# String pool flags.
UTF8_FLAG = 1 << 8

# Common typed-value data types (Android TypedValue).
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12


class AXMLError(ValueError):
    """Raised when a buffer cannot be parsed as Android binary XML."""


@dataclass
class AXMLAttribute:
    namespace: str
    name: str
    value: str
    raw_type: int
    raw_value: int


@dataclass
class AXMLElement:
    name: str
    namespace: str = ""
    attributes: list[AXMLAttribute] = field(default_factory=list)
    children: list[AXMLElement] = field(default_factory=list)
    parent: AXMLElement | None = field(default=None, repr=False)

    def attr(self, name: str, namespace: str | None = None) -> str | None:
        """Return the first attribute value matching ``name``.

        Namespace is ignored by default so callers can ask for ``debuggable``
        without caring about the android namespace URI.
        """
        for a in self.attributes:
            if a.name == name and (namespace is None or a.namespace == namespace):
                return a.value
        return None

    def iter(self):
        yield self
        for child in self.children:
            yield from child.iter()

    def findall(self, name: str) -> list[AXMLElement]:
        return [e for e in self.iter() if e.name == name]


class _StringPool:
    def __init__(self, strings: list[str]):
        self._strings = strings

    def get(self, index: int) -> str:
        if index < 0 or index >= len(self._strings):
            return ""
        return self._strings[index]

    def __len__(self) -> int:
        return len(self._strings)


def _read_string_pool(buf: bytes, offset: int) -> tuple[_StringPool, int]:
    (chunk_type, header_size, chunk_size) = struct.unpack_from("<HHI", buf, offset)
    if chunk_type != RES_STRING_POOL_TYPE:
        raise AXMLError("expected a string pool chunk")
    (string_count, style_count, flags, strings_start, styles_start) = struct.unpack_from(
        "<IIIII", buf, offset + 8
    )
    is_utf8 = bool(flags & UTF8_FLAG)
    offsets_base = offset + 28
    string_offsets = struct.unpack_from(f"<{string_count}I", buf, offsets_base)
    data_base = offset + strings_start

    strings: list[str] = []
    for so in string_offsets:
        pos = data_base + so
        try:
            if is_utf8:
                strings.append(_read_utf8_string(buf, pos))
            else:
                strings.append(_read_utf16_string(buf, pos))
        except (struct.error, IndexError, UnicodeDecodeError):
            strings.append("")
    return _StringPool(strings), offset + chunk_size


def _read_utf8_string(buf: bytes, pos: int) -> str:
    # UTF-8 pool: encoded length (in characters) then byte length, each a
    # 1-or-2-byte varint, then the bytes, then a null terminator.
    char_len, pos = _decode_utf8_len(buf, pos)
    byte_len, pos = _decode_utf8_len(buf, pos)
    data = buf[pos : pos + byte_len]
    return data.decode("utf-8", errors="replace")


def _decode_utf8_len(buf: bytes, pos: int) -> tuple[int, int]:
    first = buf[pos]
    if first & 0x80:
        second = buf[pos + 1]
        return ((first & 0x7F) << 8) | second, pos + 2
    return first, pos + 1


def _read_utf16_string(buf: bytes, pos: int) -> str:
    length = struct.unpack_from("<H", buf, pos)[0]
    pos += 2
    if length & 0x8000:
        high = length & 0x7FFF
        low = struct.unpack_from("<H", buf, pos)[0]
        length = (high << 16) | low
        pos += 2
    data = buf[pos : pos + length * 2]
    return data.decode("utf-16-le", errors="replace")


def _format_value(
    pool: _StringPool,
    res_map: list[int],
    value_type: int,
    value_data: int,
    raw_index: int,
) -> str:
    if raw_index != 0xFFFFFFFF and value_type == TYPE_STRING:
        return pool.get(raw_index)
    if value_type == TYPE_STRING:
        return pool.get(value_data)
    if value_type == TYPE_INT_BOOLEAN:
        return "true" if value_data != 0 else "false"
    if value_type == TYPE_REFERENCE:
        return f"@{value_data:#010x}"
    if value_type == TYPE_INT_HEX:
        return f"{value_data:#x}"
    if value_type == TYPE_FLOAT:
        return str(struct.unpack("<f", struct.pack("<I", value_data & 0xFFFFFFFF))[0])
    if value_type == TYPE_NULL:
        return ""
    # Default: treat as a signed decimal integer.
    signed = value_data - 0x100000000 if value_data >= 0x80000000 else value_data
    return str(signed)


def parse(buf: bytes) -> AXMLElement:
    """Parse an AXML buffer and return the root element.

    Raises :class:`AXMLError` if the buffer is not valid Android binary XML.
    """
    if len(buf) < 8:
        raise AXMLError("buffer too small to be AXML")
    magic, _header_size, _file_size = struct.unpack_from("<HHI", buf, 0)
    if magic != RES_XML_TYPE:
        raise AXMLError("not an Android binary XML file (bad magic)")

    pool: _StringPool | None = None
    res_map: list[int] = []
    offset = 8
    n = len(buf)

    root: AXMLElement | None = None
    current: AXMLElement | None = None
    ns_stack: list[str] = []

    while offset + 8 <= n:
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", buf, offset)
        if chunk_size < 8 or offset + chunk_size > n:
            break

        if chunk_type == RES_STRING_POOL_TYPE:
            pool, _end = _read_string_pool(buf, offset)
        elif chunk_type == RES_XML_RESOURCE_MAP_TYPE:
            count = (chunk_size - header_size) // 4
            # Maps attribute-name pool indices to framework resource ids. We
            # resolve names from the string pool directly, so this is kept for
            # completeness and to validate the chunk advances correctly.
            res_map[:] = struct.unpack_from(f"<{count}I", buf, offset + header_size)
        elif chunk_type == RES_XML_START_NAMESPACE_TYPE:
            ns_stack.append("ns")
        elif chunk_type == RES_XML_END_NAMESPACE_TYPE:
            if ns_stack:
                ns_stack.pop()
        elif chunk_type == RES_XML_START_ELEMENT_TYPE:
            if pool is None:
                raise AXMLError("element chunk before string pool")
            element = _parse_start_element(buf, offset, header_size, pool)
            if root is None:
                root = element
            if current is not None:
                element.parent = current
                current.children.append(element)
            current = element
        elif chunk_type == RES_XML_END_ELEMENT_TYPE:
            if current is not None and current.parent is not None:
                current = current.parent
        elif chunk_type == RES_XML_CDATA_TYPE:
            pass

        offset += chunk_size

    if root is None:
        raise AXMLError("no XML elements found")
    return root


def _parse_start_element(
    buf: bytes, offset: int, header_size: int, pool: _StringPool
) -> AXMLElement:
    # Node header (8 bytes after chunk header): lineNumber, comment.
    body = offset + header_size
    (_ns_idx, name_idx, attr_start, attr_size, attr_count, _id_idx, _class_idx, _style_idx) = (
        struct.unpack_from("<iiHHHHHH", buf, body)
    )
    name = pool.get(name_idx)
    element = AXMLElement(name=name)

    attr_base = body + attr_start
    for i in range(attr_count):
        ao = attr_base + i * attr_size
        (a_ns_idx, a_name_idx, a_raw_idx, a_typed, a_data) = struct.unpack_from("<iiiII", buf, ao)
        # a_typed packs size (low 16 bits), res0 (next 8), dataType (high 8).
        value_type = (a_typed >> 24) & 0xFF
        a_name = pool.get(a_name_idx)
        a_ns = pool.get(a_ns_idx) if a_ns_idx >= 0 else ""
        value = _format_value(pool, [], value_type, a_data, a_raw_idx & 0xFFFFFFFF)
        element.attributes.append(
            AXMLAttribute(
                namespace=a_ns,
                name=a_name,
                value=value,
                raw_type=value_type,
                raw_value=a_data,
            )
        )
    return element


def is_axml(buf: bytes) -> bool:
    """Cheap check whether a buffer looks like Android binary XML."""
    if len(buf) < 8:
        return False
    magic = struct.unpack_from("<H", buf, 0)[0]
    return magic == RES_XML_TYPE
