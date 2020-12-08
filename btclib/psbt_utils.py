from io import BytesIO
from typing import Dict, Tuple

from . import var_int
from .alias import BinaryData
from .exceptions import BTClibValueError
from .utils import bytesio_from_binarydata


def deserialize_map(data: BinaryData) -> Tuple[Dict[bytes, bytes], BytesIO]:
    stream = bytesio_from_binarydata(data)
    if (
        len(stream.getbuffer()) == stream.tell()
    ):  # we are at the end of the stream buffer
        raise BTClibValueError("malformed psbt: at least a map is missing")
    partial_map: Dict[bytes, bytes] = {}
    while True:
        if stream.read(1)[0] == 0:
            return partial_map, stream
        stream.seek(-1, 1)  # reset stream position
        key = stream.read(var_int.deserialize(stream))
        value = stream.read(var_int.deserialize(stream))
        if key in partial_map:
            raise BTClibValueError(f"duplicated key in psbt map: 0x{key.hex()}")
        partial_map[key] = value
