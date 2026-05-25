import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Hash SHA-256 du mot de passe maître (Le mot de passe en clair est "admin123") [cite: 12]
MASTER_HASH = "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9" [cite: 13, 14]

# Noms des fichiers générés [cite: 15]
KEY_FILE = "cle.key" [cite: 16]
SECRET_FILE = "secret.enc" [cite: 17]

# ==========================================
# PARTIE 1 : AUTHENTIFICATION (HASHING) [cite: 19, 21]
# ==========================================
def verifier_mot_de_passe(saisie): [cite: 22]
    # 1. Hacher la saisie en SHA-256 (ne pas oublier le encode()) [cite: 26]
    saisie_hashee = hashlib.sha256(saisie.encode()).hexdigest()
    
    # 2. Comparer l'empreinte hexadécimale avec MASTER_HASH [cite: 27]
    # 3. Retourner True si ça correspond, False sinon [cite: 28]
    return saisie_hashee == MASTER_HASH

# ==========================================
# GESTION DE LA CLÉ (Déjà codé pour vous) [cite: 35]
# ==========================================
def generer_ou_charger_cle(): [cite: 37]
    """Génère une clé AES de 32 octets si elle n'existe pas, sinon la charge.""" [cite: 38]
    if not os.path.exists(KEY_FILE): [cite: 39]
        cle = os.urandom(32) # [cite: 40]
        with open(KEY_FILE, "wb") as f: [cite: 41]
            f.write(cle) # [cite: 42]
        return cle # [cite: 43]
    else:
        with open(KEY_FILE, "rb") as f: [cite: 45, 46]
            return f.read() # [cite: 48]

# ==========================================
# PARTIE 2 : CHIFFREMENT (AES CBC) [cite: 50]
# ==========================================
def chiffrer_secret(texte_clair, cle): [cite: 53]
    # 1. Générer un IV aléatoire de 16 octets avec os.urandom [cite: 56]
    iv = os.urandom(16)
    
    # 2. Appliquer le padding PKCS7 (128 bits) sur le texte_clair [cite: 57]
    padder = padding.PKCS7(128).padder()
    texte_padde = padder.update(texte_clair.encode()) + padder.finalize()
    
    # 3. Chiffrer le texte paddé avec AES en mode CBC [cite: 58]
    cipher = Cipher(algorithms.AES(cle), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    texte_chiffre = encryptor.update(texte_padde) + encryptor.finalize()
    
    # 4. Retourner l'IV concaténé (+) au texte chiffré [cite: 59]
    return iv + texte_chiffre

def dechiffrer_secret(donnees_chiffrees, cle): [cite: 63]
    # 1. Extraire l'IV (les 16 premiers octets) et le vrai message chiffré (le reste) [cite: 65, 66]
    iv = donnees_chiffrees[:16]
    texte_chiffre = donnees_chiffrees[16:]
    
    # 2. Déchiffrer avec AES en mode CBC [cite: 67]
    cipher = Cipher(algorithms.AES(cle), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    texte_padde = decryptor.update(texte_chiffre) + decryptor.finalize()
    
    # 3. Retirer le padding PKCS7 [cite: 68]
    unpadder = padding.PKCS7(128).unpadder()
    texte_clair = unpadder.update(texte_padde) + unpadder.finalize()
    
    # 4. Retourner le texte en clair avec .decode() [cite: 69]
    return texte_clair.decode()

# ==========================================
# MENU PRINCIPAL (Ne pas modifier cette partie) [cite: 73]
# ==========================================
if __name__ == "__main__": [cite: 75, 76, 78]
    print("=== COFFRE-FORT NUMÉRIQUE ===") [cite: 79]
    mdp = input("Entrez le mot de passe maître : ") [cite: 80, 85]
    
    # Vérification de l'accès [cite: 81]
    if verifier_mot_de_passe(mdp): [cite: 82]
        print("\n[+] Accès autorisé.") [cite: 83]
        cle_aes = generer_ou_charger_cle() [cite: 84, 86]
        
        choix = input("Voulez-vous (1) Chiffrer un nouveau secret ou (2) Lire le secret actuel ?: ") [cite: 87, 88, 89]
        
        if choix == "1": [cite: 90, 92]
            secret = input("Entrez la phrase secrète à protéger : ") [cite: 93, 95, 98]
            donnees_enc = chiffrer_secret(secret, cle_aes) [cite: 94, 95]
            
            # Sauvegarde dans le fichier [cite: 96]
            if donnees_enc: [cite: 96]
                with open(SECRET_FILE, "wb") as f: [cite: 97]
                    f.write(donnees_enc) [cite: 97]
                print("[+] Secret chiffré et sauvegardé avec succès dans secret.enc!") [cite: 99, 100]
            else: [cite: 102]
                print("[-] Erreur : La fonction de chiffrement n'est pas encore implémentée.") [cite: 101, 103]
                
        elif choix == "2": [cite: 104]
            try:
                with open(SECRET_FILE, "rb") as f: [cite: 106]
                    donnees = f.read() [cite: 106]
                texte = dechiffrer_secret(donnees, cle_aes) [cite: 107]
                if texte: [cite: 108]
                    print(f"\n[+] Votre secret est : {texte}") [cite: 109]
                else: [cite: 110]
                    print("[-] Erreur : La fonction de déchiffrement n'est pas encore implémentée.") [cite: 109, 111]
            except FileNotFoundError: [cite: 111]
                print("[-] Aucun secret trouvé. Veuillez d'abord en chiffrer un.") [cite: 112, 114]
        else: [cite: 113]
            print("[-] Choix invalide.") [cite: 115]
    else:
        print("[-] Accès refusé. Alerte intrusion!") [cite: 116]