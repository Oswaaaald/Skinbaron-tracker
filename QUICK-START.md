# 🚀 Démarrage rapide sans Discord Webhook

## Configuration minimale pour Dokploy

### Variables d'environnement essentielles :

```bash
# === RÉSOLUTION CONFLIT PORTS ===
BACKEND_PORT=3001
FRONTEND_PORT=3002

# === CONFIGURATION DE BASE ===
NODE_ENV=production
PORT=8080
SQLITE_PATH=/app/data/alerts.db

# === DÉSACTIVER LES FEEDS GLOBAUX ===
ENABLE_BEST_DEALS=false
ENABLE_NEWEST_ITEMS=false

# === API CONFIGURATION ===
CORS_ORIGIN=*
NEXT_PUBLIC_API_URL=http://localhost:3001

# === AUTRES ===
POLL_CRON=*/5 * * * *
FEEDS_MAX_PRICE=200
FEEDS_MAX_WEAR=0.20
RATE_LIMIT_MAX=100
RATE_LIMIT_WINDOW=60000
LOG_LEVEL=info
```

## ✅ Fonctionnement sans webhook Discord

1. **API SkinBaron** : Fonctionne sans clé API (API publique)
2. **Feeds globaux** : Désactivés (`ENABLE_BEST_DEALS=false`)
3. **Alertes personnalisées** : Fonctionnent avec webhook Discord par règle
4. **Interface web** : Pleinement fonctionnelle

## 🎯 Comment utiliser l'application

### 1. Accéder à l'interface
- Frontend : `http://votre-serveur:3002`
- API : `http://votre-serveur:3001`

### 2. Créer une règle avec webhook Discord
```bash
curl -X POST http://votre-serveur:3001/api/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Mon alerte AK-47",
    "weaponName": "AK-47", 
    "maxPrice": 100,
    "discordWebhook": "https://discord.com/api/webhooks/VOTRE_WEBHOOK"
  }'
```

### 3. Démarrer la surveillance
```bash
curl -X POST http://votre-serveur:3001/api/system/scheduler/start
```

## 💡 Pour obtenir un webhook Discord

1. **Aller sur votre serveur Discord**
2. **Paramètres du canal → Intégrations → Webhooks**
3. **Créer un webhook**
4. **Copier l'URL**

## 📊 Tester l'API

```bash
# Santé de l'API
curl http://votre-serveur:3001/api/health

# Statut système
curl http://votre-serveur:3001/api/system/status

# Liste des règles
curl http://votre-serveur:3001/api/rules
```

---

L'application **fonctionne parfaitement** sans clé API SkinBaron et sans webhook Discord global ! 🎯