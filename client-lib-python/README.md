# VaultCode — client-lib-python

Runtime client per **proteggere script/logica Python** (es. prompt e logica di
agenti AI, formule, regole di business). Porting 1:1 della `client-lib-php`, con
**parità crittografica**: un payload prodotto dal protect-tool è decifrabile sia
da PHP sia da Python (stesso key-server, stesso formato).

## Installazione
```bash
pip install ./client-lib-python      # oppure: pip install vaultcode-client (se pubblicato)
```
Dipendenza: `cryptography`.

## Uso
Nel bootstrap dell'app/script, una volta:
```python
from vaultcode import Runtime, Config
Runtime.init(Config.from_json_file('vaultcode.config.json'))
```
I file **protetti** (generati dal protect-tool) contengono:
```python
VAULTCODE_RIGHTS_TAG = "…"
from vaultcode import Runtime as _vc
exec(_vc.fragment('mod', 'frag', 1), globals())   # definisce funzioni/costanti del know-how
```

## Modello di protezione (IMPORTANTE, diverso dal PHP)
In Python `exec` dentro una funzione **non** riscrive i locali. Quindi si protegge
SOLO a livello di **funzione / classe / modulo** (def, class, costanti/prompt):
```python
#%[vaultcode:protect module="bot" id="prompt" ck=1]
SYSTEM_PROMPT = "..."
def classifica(x): ...
#%[/vaultcode:protect]
```
NON marcare blocchi a metà di una funzione che assegnano variabili locali lette
dopo. Per i frammenti dentro loop usa `loop=1` (memoizzazione).

## Resilienza (non bloccante)
Cascata key-server → cache locale (TTL/grace) → escrow → banner. Se il server è
irraggiungibile lo script **continua** (la porzione non eseguita degrada con
grazia). Nessun meccanismo distruttivo (INVARIANTE 1).

## API principali
- `Runtime.init(cfg)` / `Runtime.fragment(module, frag, ck, memo=False) -> str`
- `Runtime.is_compromised()`, `Runtime.integrity_warnings()`, `Runtime.scan()`
- `Runtime.integrity_badge()` → badge HTML per app web Python (Flask/Django)

## Hardening (opzionale, §9 build spec)
Il sorgente decifrato è in RAM all'`exec` (come l'`eval` PHP). Per alzare il costo,
compila i moduli di maggior valore con **Cython/Nuitka** e disabilita i `.pyc`
(`sys.dont_write_bytecode = True`). VaultCode resta selettività + provabilità +
watermark; root-wins è un limite onesto e dichiarato.
