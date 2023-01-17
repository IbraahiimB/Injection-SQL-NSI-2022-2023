import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36(KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
#Ici on a défini l'agent utilisateur

url = "http://professeurgibaud.ovh/"
def get_all_forms(url):
    """
Étant donné une `url`, cette fonction renvoie tous les formulaires du contenu HTML
    """
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")
print(get_all_forms(url))


form = get_all_forms(url)[0]
def get_form_details(form):
    """
   Cette fonction extrait toutes les informations utiles possibles sur un `formulaire` HTML
    """
    details = {}
    
# obtenir l'action du formulaire (URL cible)
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
# obtenir la méthode du formulaire (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
   # obtenir tous les détails d'entrée tels que le type et le nom
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})

# mettre tout dans le dictionnaire résultant
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details
#Donner les détails d'un formulaires WEB
#print(get_form_details(form))

def is_vulnerable(response):
    errors = {
        # MySQL
        "vous avez une erreur dans votre syntaxe sql ;",
        "attention : mysql",
        # Serveur SQL
        "Unclosed suivi de guillemets après la chaîne de caractères",
        # Oracle
        "la chaîne entre guillemets n'est pas correctement terminée",
    }
    for error in errors:
        # si vous trouvez une de ces erreurs, retournez True
        if error in response.content.decode().lower():
            return True
    # aucune erreur détectée
    return False


def scan_sql_injection(url):
    # test on URL
    for c in "\"'":
        
# ajouter un guillemet/guillemet double à l'URL
        new_url = f"{url}{c}"
        print("[!] Trying", new_url)
       # faire la requête HTTP
        res = s.get(new_url)
        if is_vulnerable(res):
            
# Injection SQL détectée sur l'URL elle-même,
            # pas besoin de précéder pour extraire les formulaires et les soumettre
            print("[+] SQL Injection vulnerability detected, link:", new_url)
            return
    
# test sur les formulaires HTML
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            
# le corps de données que nous voulons soumettre
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                  # tout formulaire de saisie caché ou ayant une certaine valeur,
                    # il suffit de l'utiliser dans le corps du formulaire
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                  
# tous les autres sauf submit, utilisez des données indésirables avec un caractère spécial
                    data[input_tag["name"]] = f"test{c}"
            # joignez l'url à l'action (URL de demande de formulaire)
            url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = s.post(url, data=data)
            elif form_details["method"] == "get":
                res = s.get(url, params=data)
         
# teste si la page résultante est vulnérable
            if is_vulnerable(res):
                print("[+] SQL Injection vulnerability detected, link:", url)
                print("[+] Form:")
                pprint(form_details)
                break
#Fonction qui vérifie la vulnérabilité de l'URL 
print(scan_sql_injection(url))

