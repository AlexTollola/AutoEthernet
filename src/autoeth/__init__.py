"""autoeth - Automotive Ethernet learning project (Python).

Simple layered architecture:
  - autoeth.core.transport       : UDP/TCP primitives
  - autoeth.core.serialization   : DBC-like signal encoding/decoding
  - autoeth.core.config          : single-file catalog loader (used in later steps)
  - autoeth.protocols.someip     : protocol wrappers (used in later steps)
"""

__all__ = ["core", "protocols"]
