"""
DIGICHEESE — mini-app de démonstration pour le TD « exploiter / corriger une CVE ».

Elle est volontairement piégée : elle utilise Jinja2 **3.1.2**, affecté par
CVE-2024-22195 (GHSA-h5c8-rqwp-cp95). Sur cette version, le filtre `xmlattr`
n'interdit pas les **clés** d'attribut contenant des espaces. L'app permet
justement de contrôler une telle clé.

Étapes du TD (voir le chapitre 09 du cours DiginamicAcademy/cours-securite-vulnerabilites-attaques) :
  1. exploiter la faille sur cet environnement de test ;
  2. documenter le mécanisme (clés d'attribut non validées) ;
  3. corriger (Jinja2 >= 3.1.3 **et** validation des clés) et vérifier que
     l'exploit ne passe plus.
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

PAGE = """
<!doctype html>
<title>DIGICHEESE — recherche</title>
<h1>Recherche catalogue</h1>
<form>
  <input name="q" value="{{ q }}" placeholder="nom du produit">
  <button>Chercher</button>
</form>
<p>Tri : <a href="/?q={{ q }}&tri=nom">par nom</a> · <a href="/?q={{ q }}&tri=prix">par prix</a></p>
<ul>
{% for p in products %}
  {# xmlattr assemble les attributs de la balise <li> à partir d'un dict.
     Sur Jinja2 < 3.1.3 (CVE-2024-22195), les CLÉS contenant des espaces
     passent telles quelles : une clé piégée peut ajouter un attribut HTML,
     par exemple un gestionnaire d'événement. #}
  <li {{ attributs|xmlattr }}>{{ p }}</li>
{% endfor %}
</ul>
"""

PRODUCTS = [
    "Comté 12 mois",
    "Brie de Meaux",
    "Roquefort",
    "Saint-Nectaire",
    "Beaufort d'alpage",
]


@app.get("/")
def search():
    q = request.args.get("q", "")
    tri = request.args.get("tri", "nom")  # clé d'attribut pilotée par la requête
    found = [p for p in PRODUCTS if q.lower() in p.lower()] if q else PRODUCTS
    attributs = {
        "data-nom": q or "tous",
        tri: "1",  # FAILLE : la clé n'est pas validée
    }
    return render_template_string(PAGE, products=found, q=q, attributs=attributs)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
