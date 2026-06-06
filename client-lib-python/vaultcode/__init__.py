"""VaultCode — client runtime per script Python (porting 1:1 di client-lib-php).

Decifra a runtime le porzioni protette (know-how) richiedendo la chiave al
key-server, con cascata di fallback non bloccante. Parità crittografica con PHP e
protect-tool: un payload vale per entrambi i linguaggi.

Uso (nel bootstrap dell'app/script):

    from vaultcode import Runtime, Config
    Runtime.init(Config.from_json_file('vaultcode.config.json'))

I file protetti (generati dal protect-tool) contengono:
    VAULTCODE_RIGHTS_TAG = "..."
    from vaultcode import Runtime as _vc
    exec(_vc.fragment('mod','frag',1), globals())
"""

from .config import Config
from .runtime import VERSION, Runtime

__all__ = ["Runtime", "Config", "VERSION"]
__version__ = VERSION
