import requests
import os

# --- CONFIGURATION ---
# Remplace la chaîne de caractères ci-dessous par ta véritable clé API Groq.
# C'est la seule ligne que tu dois modifier.
GROQ_API_KEY = "# note share this key"

# --- LA REQUÊTE ---
# On prépare les informations pour l'envoi
headers = {
    "Authorization": f"Bearer {GROQ_API_KEY}",
    "Content-Type": "application/json",
}

data = {
    "model": "llama3-8b-8192",  # Un modèle Llama 3 rapide et efficace
    "messages": [
        {
            "role": "user",
            # La question qu'on pose à l'IA. On reste dans ton domaine !
            "content": "Explique la faille de sécurité XSS en trois phrases simples."
        }
    ]
}

# --- L'APPEL API ---
print("Envoi de la requête à l'API Groq...")
try:
    response = requests.post("https://api.groq.com/openai/v1/chat/completions", json=data, headers=headers)

    # --- VÉRIFICATION DE LA RÉPONSE ---
    if response.status_code == 200:
        print("Succès ! Réponse reçue.")
        # On extrait le texte de la réponse
        result_text = response.json()['choices'][0]['message']['content']
        print("\n--- Réponse de Llama 3 ---")
        print(result_text)
        print("--------------------------\n")
    else:
        # En cas d'erreur, on affiche le code et le message d'erreur
        print(f"Erreur ! Code: {response.status_code}")
        print(f"Message: {response.text}")

except requests.exceptions.RequestException as e:
    print(f"Une erreur de connexion est survenue : {e}")