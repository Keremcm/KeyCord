from cryptography.fernet import Fernet
from pathlib import Path

KEY = b"34yn-1EfvJlx4N_DYHdoojxnfHlDuaA7Ty02TU5vyg8="
f = Fernet(KEY)

with open("security.log", "r", encoding="utf-8") as inp, \
     open("cikti.txt", "w", encoding="utf-8") as out:
    
    for i, line in enumerate(inp):
        stripped = line.strip()
        # Fernet tokenlar hep gAAAAA ile başlar
        if stripped.startswith("gAAAAA"):
            try:
                decrypted = f.decrypt(stripped.encode()).decode("utf-8")
                out.write(decrypted + "\n")
            except Exception:
                out.write(line)  # çözülemediyse orijinali yaz
        else:
            out.write(line)
        
        if i % 10000 == 0:
            print(f"{i} satır işlendi...")

print("✓ Tamamlandı")
