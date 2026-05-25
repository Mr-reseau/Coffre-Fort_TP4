import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Hash SHA-256 du mot de passe maître (mot de passe = "admin123")
MASTER_HASH = "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9"

# Noms des fichiers générés
KEY_FILE = "cle.key"
SECRET_FILE = "secret.enc"


# ==========================================
# PARTIE 1 : AUTHENTIFICATION (HASHING)
# ==========================================

def verifier_mot_de_passe(saisie):
    """
    Vérifie le mot de passe maître
    """
    hash_saisie = hashlib.sha256(saisie.encode()).hexdigest()
    return hash_saisie == MASTER_HASH


# ==========================================
# GESTION DE LA CLÉ
# ==========================================

def generer_ou_charger_cle():
    """Génère ou charge la clé AES"""
    if not os.path.exists(KEY_FILE):
        cle = os.urandom(32)
        with open(KEY_FILE, "wb") as f:
            f.write(cle)
        return cle
    else:
        with open(KEY_FILE, "rb") as f:
            return f.read()


# ==========================================
# PARTIE 2 : CHIFFREMENT (AES CBC)
# ==========================================

def chiffrer_secret(texte_clair, cle):
    """
    Chiffre un texte avec AES CBC
    """

    # 1. IV
    iv = os.urandom(16)

    # 2. Padding PKCS7
    padder = padding.PKCS7(128).padder()
    texte_padde = padder.update(texte_clair.encode()) + padder.finalize()

    # 3. AES CBC
    cipher = Cipher(algorithms.AES(cle), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    texte_chiffre = encryptor.update(texte_padde) + encryptor.finalize()

    # 4. Retour IV + ciphertext
    return iv + texte_chiffre


def dechiffrer_secret(donnees_chiffrees, cle):
    """
    Déchiffre un texte AES CBC
    """

    # 1. Extraire IV
    iv = donnees_chiffrees[:16]
    texte_chiffre = donnees_chiffrees[16:]

    # 2. AES CBC
    cipher = Cipher(algorithms.AES(cle), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    texte_padde = decryptor.update(texte_chiffre) + decryptor.finalize()

    # 3. Retirer padding
    unpadder = padding.PKCS7(128).unpadder()
    texte_clair = unpadder.update(texte_padde) + unpadder.finalize()

    # 4. Retour texte lisible
    return texte_clair.decode()


# ==========================================
# MENU PRINCIPAL
# ==========================================

if __name__ == "__main__":
    print("=== COFFRE-FORT NUMÉRIQUE ===")

    mdp = input("Entrez le mot de passe maître : ")

    if verifier_mot_de_passe(mdp):
        print("\n[+] Accès autorisé")

        cle = generer_ou_charger_cle()

        choix = input("(1) Chiffrer ou (2) Lire secret ? : ")

        if choix == "1":
            secret = input("Entrez le secret : ")
            data = chiffrer_secret(secret, cle)

            with open(SECRET_FILE, "wb") as f:
                f.write(data)

            print("[+] Secret chiffré")

        elif choix == "2":
            try:
                with open(SECRET_FILE, "rb") as f:
                    data = f.read()

                print("[🔓] Secret :", dechiffrer_secret(data, cle))

            except FileNotFoundError:
                print("[-] Aucun secret trouvé")

        else:
            print("Choix invalide")

    else:
        print("[-] Accès refusé")