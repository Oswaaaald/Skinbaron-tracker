# 🎯 SkinBaron Alerts

Application full-stack TypeScript pour surveiller les offres de skins CS2 sur SkinBaron avec notifications Discord personnalisées.

## 📋 Fonctionnalités

- **👤 Gestion personnalisée** : Chaque utilisateur peut configurer ses propres webhooks Discord et alertes
- **🔍 Surveillance automatique** : Monitoring en temps réel des nouvelles offres SkinBaron
- **📊 Filtres avancés** : Prix, usure, qualité, noms d'armes personnalisables
- **🔔 Notifications Discord** : Alertes riches avec embeds et informations détaillées
- **⚡ Performance** : API Fastify rapide avec base SQLite optimisée
- **🐳 Déploiement** : Support Docker complet pour Dokploy

## 🚀 Démarrage rapide

### Prérequis

- Node.js 20+
- Docker & Docker Compose (optionnel)
- Webhook Discord (pour les notifications)

### Installation locale

```bash
# Cloner et accéder au projet
git clone <votre-repo>
cd skinbaron-alerts-sbapi

# Démarrer en développement local
./dev.sh dev-local
```

### Installation avec Docker

```bash
# Démarrage développement avec Docker
./dev.sh dev-docker

# Ou production
./dev.sh prod-docker
```

## 🏗️ Architecture

### Backend (`/backend`)

**Stack technique :**
- Fastify 4.x (Serveur API haute performance)
- TypeScript (Type safety)
- better-sqlite3 (Base de données locale)
- Zod (Validation des schémas)
- Cron (Planification des tâches)

**Structure :**
```
backend/src/
├── index.ts              # Serveur principal Fastify
├── lib/
│   ├── config.ts         # Configuration environnement
│   ├── store.ts          # Gestion SQLite
│   ├── sbclient.ts       # Client API SkinBaron
│   ├── scheduler.ts      # Moteur de surveillance
│   └── notifier.ts       # Notifications Discord
└── routes/
    ├── rules.ts          # API règles d'alerte
    └── alerts.ts         # API historique alertes
```

### Frontend (`/frontend`)

**Stack technique :**
- Next.js 15 (App Router)
- TypeScript
- Tailwind CSS
- shadcn/ui (Composants)
- TanStack Query (State management)
- React Hook Form + Zod

**Structure :**
```
frontend/src/
├── app/
│   ├── layout.tsx        # Layout principal
│   └── page.tsx          # Dashboard
├── components/
│   ├── dashboard.tsx     # Interface principale
│   ├── rules-table.tsx   # Gestion des règles
│   ├── alerts-table.tsx  # Historique alertes
│   └── ui/              # Composants shadcn/ui
└── lib/
    ├── api.ts           # Client API
    └── utils.ts         # Utilitaires
```

## 📚 Utilisation

### 1. Configuration initiale

Copiez et configurez les variables d'environnement :

```bash
# Backend
cp backend/.env.example backend/.env
# Modifier PORT, DISCORD_WEBHOOK, etc.

# Frontend
cp frontend/.env.example frontend/.env.local
# Modifier NEXT_PUBLIC_API_URL si nécessaire
```

### 2. Créer une règle d'alerte

```bash
curl -X POST http://localhost:8080/api/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "AK-47 Redline pas cher",
    "weaponName": "AK-47",
    "skinName": "Redline",
    "maxPrice": 50,
    "maxWear": 0.25,
    "minQuality": "Field-Tested",
    "discordWebhook": "https://discord.com/api/webhooks/..."
  }'
```

### 3. Gérer le scheduler

```bash
# Démarrer la surveillance
curl -X POST http://localhost:8080/api/system/scheduler/start

# Arrêter
curl -X POST http://localhost:8080/api/system/scheduler/stop

# Statut
curl http://localhost:8080/api/system/status
```

## 🔧 API Endpoints

### Rules (Règles d'alerte)
- `GET /api/rules` - Liste des règles
- `POST /api/rules` - Créer une règle
- `PUT /api/rules/:id` - Modifier une règle
- `DELETE /api/rules/:id` - Supprimer une règle

### Alerts (Historique)
- `GET /api/alerts` - Liste des alertes envoyées
- `GET /api/alerts/stats` - Statistiques

### System (Système)
- `GET /api/system/status` - État du système
- `POST /api/system/scheduler/start` - Démarrer surveillance
- `POST /api/system/scheduler/stop` - Arrêter surveillance
- `GET /api/health` - Health check

## 🐳 Docker & Dokploy

### Images Docker

```bash
# Build production
docker-compose build

# Développement avec hot reload
docker-compose -f docker-compose.dev.yml up

# Production
docker-compose up -d
```

### Déploiement Dokploy

1. **Préparer l'environnement :**
   ```bash
   # Créer .env avec vos vraies valeurs
   cp backend/.env.example backend/.env
   cp frontend/.env.example frontend/.env.local
   ```

2. **Configurer Dokploy :**
   - Repository : votre repo Git
   - Docker Compose : `docker-compose.yml`
   - Variables d'environnement via l'interface Dokploy

3. **Variables importantes :**
   ```bash
   # Backend
   NODE_ENV=production
   PORT=8080
   DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
   
   # Frontend  
   NEXT_PUBLIC_API_URL=https://votre-backend-url.com
   ```

## 🛠️ Scripts de développement

Le script `./dev.sh` fournit plusieurs commandes :

```bash
./dev.sh dev-local      # Développement local (sans Docker)
./dev.sh dev-docker     # Développement avec Docker
./dev.sh prod-docker    # Production avec Docker
./dev.sh build          # Build images Docker
./dev.sh clean          # Nettoyer containers/images
./dev.sh help           # Aide
```

## 🔍 Surveillance SkinBaron

### Sources de données
- **Search API** : Recherche par critères utilisateur
- **Best Deals** : Meilleures offres du moment
- **Newest Items** : Derniers items ajoutés

### Logique de filtrage
```typescript
// Exemple de règle
{
  weaponName: "AK-47",
  skinName: "Redline", 
  maxPrice: 50,
  maxWear: 0.25,
  minQuality: "Field-Tested"
}

// Correspondra aux items :
// - AK-47 Redline Field-Tested à 45€ avec 0.20 d'usure ✅
// - AK-47 Redline Battle-Scarred à 30€ avec 0.50 d'usure ❌ (usure > 0.25)
```

### Déduplication
- Les alertes sont dédupliquées par `itemId`
- Historique conservé en base SQLite
- Pas de spam sur Discord

## 📊 Monitoring

### Health checks
```bash
# API disponibilité
curl http://localhost:8080/api/health

# Statut complet système
curl http://localhost:8080/api/system/status
```

### Logs
- Backend : Logs structurés Fastify/Pino
- Frontend : Logs Next.js standard
- Docker : `docker-compose logs -f`

## 🤝 Contribution

1. Fork le projet
2. Créer une branche feature (`git checkout -b feature/amazing-feature`)
3. Commit (`git commit -m 'Add amazing feature'`)
4. Push (`git push origin feature/amazing-feature`)
5. Ouvrir une Pull Request

## 📄 Licence

MIT License - voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 🆘 Support

- **Issues** : GitHub Issues pour les bugs et suggestions
- **Documentation** : Ce README et les commentaires dans le code
- **API** : Documentation OpenAPI disponible sur `/api/documentation`

---

Made with ❤️ for the CS2 community