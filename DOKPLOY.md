# Configuration Dokploy pour SkinBaron Alerts

## 📋 Prérequis Dokploy

1. **Repository Git** configuré avec ce projet
2. **Variables d'environnement** configurées dans Dokploy
3. **Docker Compose** activé pour le déploiement

## 🔧 Configuration Dokploy

### 1. Paramètres généraux
- **Build Type** : Docker Compose
- **Compose File** : `docker-compose.yml`
- **Context Path** : `/` (racine du projet)

### 2. Variables d'environnement requises

#### Backend
```bash
NODE_ENV=production
PORT=8080
DATABASE_PATH=./data/skinbaron-alerts.db

# Discord (optionnel pour tests)
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_WEBHOOK_HERE

# SkinBaron API (utilise l'API publique par défaut)
# SB_API_KEY=your_api_key_if_needed

# Polling Configuration
POLL_INTERVAL_MINUTES=5
MAX_ALERTS_PER_RULE=10

# CORS Configuration
CORS_ORIGIN=https://your-frontend-domain.com
RATE_LIMIT_MAX=100
RATE_LIMIT_WINDOW=60000

# Logging
LOG_LEVEL=info
```

#### Frontend
```bash
NEXT_PUBLIC_API_URL=https://your-backend-domain.com
```

### 3. Configuration réseau Dokploy

#### Backend Service
- **Port interne** : 8080
- **Domain/Subdomain** : `api.your-domain.com`
- **Health Check Path** : `/api/health`

#### Frontend Service  
- **Port interne** : 3000
- **Domain/Subdomain** : `app.your-domain.com`
- **Health Check Path** : `/`

### 4. Volumes persistants

Dokploy configurera automatiquement :
- `skinbaron_data:/app/data` (base SQLite backend)

## 🚀 Déploiement étape par étape

### Étape 1 : Préparer le repository
1. Pusher ce code sur votre repository Git
2. S'assurer que tous les fichiers sont commitués

### Étape 2 : Créer l'application Dokploy
1. Aller sur votre instance Dokploy
2. Créer une nouvelle application
3. Connecter votre repository Git

### Étape 3 : Configurer le build
1. **Build Type** : Docker Compose
2. **Dockerfile Path** : Laisser vide (utilise docker-compose.yml)
3. **Build Context** : `/`

### Étape 4 : Variables d'environnement
Ajouter toutes les variables listées ci-dessus dans l'interface Dokploy

### Étape 5 : Configuration des domaines
1. **Backend** : Configurer le domaine pour l'API
2. **Frontend** : Configurer le domaine pour l'interface
3. **SSL** : Activer Let's Encrypt

### Étape 6 : Déployement
1. Cliquer sur "Deploy"
2. Suivre les logs de build
3. Vérifier les health checks

## 🔍 Vérification post-déploiement

### Tests de santé
```bash
# API Backend
curl https://api.your-domain.com/api/health
# Devrait retourner : {"status": "ok", "timestamp": "..."}

# Interface Frontend
curl https://app.your-domain.com
# Devrait retourner la page HTML

# Statut système complet
curl https://api.your-domain.com/api/system/status
```

### Tests fonctionnels

1. **Créer une règle via API :**
```bash
curl -X POST https://api.your-domain.com/api/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Rule",
    "weaponName": "AK-47",
    "maxPrice": 100,
    "discordWebhook": "https://discord.com/api/webhooks/your-webhook"
  }'
```

2. **Démarrer le scheduler :**
```bash
curl -X POST https://api.your-domain.com/api/system/scheduler/start
```

3. **Vérifier l'interface web :**
   - Aller sur `https://app.your-domain.com`
   - Vérifier que l'interface charge
   - Créer une règle via l'interface

## 🐛 Debugging

### Logs Dokploy
- Utiliser l'interface Dokploy pour voir les logs en temps réel
- Vérifier les logs de build et de runtime

### Problèmes fréquents

#### 1. Variables d'environnement manquantes
**Symptôme** : Service ne démarre pas
**Solution** : Vérifier toutes les variables requises dans Dokploy

#### 2. Problème de CORS
**Symptôme** : Frontend ne peut pas contacter l'API
**Solution** : Vérifier `CORS_ORIGIN` et `NEXT_PUBLIC_API_URL`

#### 3. Base de données
**Symptôme** : Erreurs SQLite
**Solution** : Vérifier que le volume persistant est configuré

#### 4. Discord Webhook
**Symptôme** : Pas de notifications
**Solution** : Vérifier l'URL du webhook Discord

### Commandes de debugging
```bash
# Statut des containers
docker ps

# Logs backend
docker logs skinbaron-alerts-backend

# Logs frontend  
docker logs skinbaron-alerts-frontend

# Entrer dans le container backend
docker exec -it skinbaron-alerts-backend sh

# Vérifier la base de données
docker exec -it skinbaron-alerts-backend sqlite3 /app/data/skinbaron-alerts.db ".tables"
```

## 📊 Monitoring en production

### Métriques importantes
- **Health checks** : API et Frontend
- **Database size** : Croissance de la base SQLite
- **Alert frequency** : Nombre d'alertes envoyées
- **API response times** : Performance des endpoints

### Alertes recommandées
- API indisponible > 5 minutes
- Espace disque < 10% (base SQLite)
- Erreurs Discord webhook > 10/heure
- Memory usage > 80%

## 🔄 Mises à jour

### Déploiement de nouvelles versions
1. Pusher le code sur la branche principale
2. Dokploy redéploiera automatiquement (si configuré)
3. Ou déclencher manuellement via l'interface

### Backup de données
```bash
# Exporter la base de données avant mise à jour
docker exec skinbaron-alerts-backend sqlite3 /app/data/skinbaron-alerts.db .dump > backup.sql
```

---

Cette configuration vous permettra de déployer SkinBaron Alerts sur Dokploy de manière optimale ! 🚀