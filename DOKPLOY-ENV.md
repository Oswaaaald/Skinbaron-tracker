# 🔧 Configuration Dokploy - Variables d'environnement

## ⚡ Configuration rapide

Copier ces variables dans l'interface Dokploy (Settings → Environment Variables) :

### Variables OBLIGATOIRES à modifier :

```bash
# 1. RÉSOUDRE LE CONFLIT DE PORT
BACKEND_PORT=3001
FRONTEND_PORT=3002

# 2. WEBHOOK DISCORD (REMPLACER PAR LE VÔTRE)
DISCORD_WEBHOOK=https://discord.com/api/webhooks/VOTRE_WEBHOOK_ICI

# 3. URL DE L'API (ADAPTER À VOTRE DOMAINE)
NEXT_PUBLIC_API_URL=https://votre-backend.dokploy.com

# 4. CORS (ADAPTER À VOTRE FRONTEND)
CORS_ORIGIN=https://votre-frontend.dokploy.com
```

### Variables par défaut (copier telles quelles) :

```bash
NODE_ENV=production
PORT=8080
SQLITE_PATH=/app/data/alerts.db
POLL_CRON=*/5 * * * *
ENABLE_BEST_DEALS=true
ENABLE_NEWEST_ITEMS=true
FEEDS_MAX_PRICE=200
FEEDS_MAX_WEAR=0.20
RATE_LIMIT_MAX=100
RATE_LIMIT_WINDOW=60000
LOG_LEVEL=info
```

## 📝 Comment procéder :

### 1. Aller dans Dokploy
- Sélectionner votre application
- Aller dans "Settings" ou "Environment"

### 2. Ajouter chaque variable
Copier une par une ces variables :
```
BACKEND_PORT → 3001
FRONTEND_PORT → 3002
DISCORD_WEBHOOK → https://discord.com/api/webhooks/VOTRE_WEBHOOK
NODE_ENV → production
PORT → 8080
...etc
```

### 3. Adapter les URLs
Une fois déployé, Dokploy vous donnera des URLs. Modifier alors :
```bash
NEXT_PUBLIC_API_URL=https://votre-vraie-url-backend
CORS_ORIGIN=https://votre-vraie-url-frontend
```

### 4. Redéployer
Cliquer "Deploy" ou "Redeploy" après avoir ajouté les variables.

## 🎯 Variables critiques à ne pas oublier :

1. **BACKEND_PORT=3001** : Évite le conflit port 8080
2. **DISCORD_WEBHOOK** : Pour recevoir les alertes
3. **NEXT_PUBLIC_API_URL** : Pour que le frontend contacte l'API
4. **CORS_ORIGIN** : Pour autoriser les requêtes frontend

## ✅ Test après déploiement :

```bash
# Test API
curl https://votre-backend.dokploy.com/api/health

# Test interface
curl https://votre-frontend.dokploy.com
```

---

💡 **Astuce** : Commencer avec `CORS_ORIGIN=*` pour tester, puis restreindre à votre domaine frontend une fois que tout fonctionne.