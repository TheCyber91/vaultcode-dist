"""VaultCode watcher di integrità (lato cliente) — §9.

Monitora SOLO i file dell'opera protetta (contro il manifest SHA-256), segnala
all'autore alterazioni che intaccano copyright/paternità o il core protetto.
Dati minimi, dichiarato, NON bloccante, mai sorveglianza del sistema cliente.
"""

__version__ = "1.0.4"  # risoluzione autonoma dei percorsi (multi-albero) nel watcher
