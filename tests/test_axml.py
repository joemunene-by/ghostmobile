"""Tests for the binary AXML decoder and the encoder used by fixtures."""

from __future__ import annotations

import pytest

from ghostmobile import axml
from ghostmobile.axml import AXMLError, is_axml, parse
from tests import samples


def test_decoder_recovers_element_and_attribute_values():
    buf = samples.encode_vulnerable_manifest()
    assert is_axml(buf)
    root = parse(buf)

    assert root.name == "manifest"
    assert root.attr("package") == "com.ghostmobile.vuln"

    uses_sdk = root.findall("uses-sdk")[0]
    assert uses_sdk.attr("minSdkVersion") == "19"
    assert uses_sdk.attr("targetSdkVersion") == "33"

    app = root.findall("application")[0]
    assert app.attr("debuggable") == "true"
    assert app.attr("allowBackup") == "true"
    assert app.attr("usesCleartextTraffic") == "true"


def test_decoder_recovers_nested_components():
    buf = samples.encode_vulnerable_manifest()
    root = parse(buf)
    activities = root.findall("activity")
    assert len(activities) == 1
    assert activities[0].attr("name") == ".MainActivity"
    assert activities[0].attr("exported") == "true"

    providers = root.findall("provider")
    assert providers[0].attr("name") == ".LeakyProvider"


def test_decoder_recovers_permissions():
    buf = samples.encode_vulnerable_manifest()
    root = parse(buf)
    perms = [p.attr("name") for p in root.findall("uses-permission")]
    assert "android.permission.READ_SMS" in perms
    assert "android.permission.INTERNET" in perms


def test_clean_manifest_round_trip():
    buf = samples.encode_clean_manifest()
    root = parse(buf)
    assert root.attr("package") == "com.ghostmobile.clean"
    app = root.findall("application")[0]
    assert app.attr("debuggable") == "false"
    assert app.attr("allowBackup") == "false"


def test_parse_rejects_non_axml():
    assert not is_axml(b"<?xml version='1.0'?><manifest/>")
    with pytest.raises(AXMLError):
        parse(b"<?xml version='1.0'?><manifest/>")


def test_parse_rejects_tiny_buffer():
    with pytest.raises(AXMLError):
        parse(b"\x03\x00")


def test_chunk_type_constants_present():
    # Guard against accidental constant drift the encoder relies on.
    assert axml.RES_XML_TYPE == 0x0003
    assert axml.RES_STRING_POOL_TYPE == 0x0001
