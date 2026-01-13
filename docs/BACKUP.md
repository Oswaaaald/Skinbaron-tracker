# 💾 Guide de Backup & Restauration

## 📋 Backups Automatiques

### Configuration Initiale (à faire une fois)

```bash
# Sur le serveur de production
ssh oswaaaald@37.59.102.200 -p 55555

# Créer le dossier de backup
sudo mkdir -p /var/backups/skinbaron
sudo chown oswaaaald:oswaaaald /var/backups/skinbaron

# Rendre les scripts exécutables
chmod +x /path/to/scripts/backup-db.sh
chmod +x /path/to/scripts/restore-db.sh
```

### Ajouter au Cron (Backup quotidien à 3h du matin)

```bash
# Éditer le crontab
crontab -e

# Ajouter cette ligne :
0 3 * * * /home/oswaaaald/skinbaron-tracker/scripts/backup-db.sh >> /var/log/skinbaron-backup.log 2>&1
```

### Backup Manuel

```bash
# Exécuter le script manuellement
./scripts/backup-db.sh
```

**Sortie attendue :**
```
[INFO] Création du dossier de backup...
[INFO] Sauvegarde du volume skinbaron_backend_data...
[INFO] ✅ Backup créé : alerts-20260113_030000.tar.gz (172K)
[INFO] Nettoyage des backups > 30 jours...
[INFO] Backups disponibles :
-rw-r--r-- 1 oswaaaald oswaaaald 172K Jan 13 03:00 alerts-20260113_030000.tar.gz
[INFO] ✅ Backup terminé avec succès !
```

---

## 🔄 Restauration

### Lister les backups disponibles

```bash
ls -lh /var/backups/skinbaron/
```

### Restaurer un backup

```bash
# Restaurer le backup le plus récent
./scripts/restore-db.sh /var/backups/skinbaron/alerts-20260113_030000.tar.gz

# Ou juste le nom du fichier
./scripts/restore-db.sh alerts-20260113_030000.tar.gz
```

**⚠️ ATTENTION :** La restauration :
1. Arrête le backend
2. Efface les données actuelles
3. Restaure le backup
4. Redémarre le backend

---

## ☁️ Backup Distant (Optionnel mais Recommandé)

### Avec Rclone (Backblaze B2 / AWS S3 / Google Drive)

```bash
# Installer rclone
curl https://rclone.org/install.sh | sudo bash

# Configurer un remote
rclone config

# Synchroniser les backups
rclone sync /var/backups/skinbaron remote:skinbaron-backups

# Ajouter au cron (tous les jours à 4h)
0 4 * * * rclone sync /var/backups/skinbaron remote:skinbaron-backups
```

### Avec rsync (serveur distant)

```bash
# Synchroniser vers un autre serveur
rsync -avz /var/backups/skinbaron/ user@backup-server:/backups/skinbaron/

# Ajouter au cron
0 4 * * * rsync -avz /var/backups/skinbaron/ user@backup-server:/backups/skinbaron/
```

---

## 🧪 Test de Restauration (à faire régulièrement)

```bash
# 1. Créer un backup de test
./scripts/backup-db.sh

# 2. Noter quelques données actuelles
docker exec skinbaron-tracker-backend node -e \
  "const db = require('better-sqlite3')('/app/data/alerts.db'); \
   console.log(db.prepare('SELECT COUNT(*) as count FROM alerts').get());"

# 3. Restaurer le backup
./scripts/restore-db.sh alerts-YYYYMMDD_HHMMSS.tar.gz

# 4. Vérifier que les données correspondent
docker exec skinbaron-tracker-backend node -e \
  "const db = require('better-sqlite3')('/app/data/alerts.db'); \
   console.log(db.prepare('SELECT COUNT(*) as count FROM alerts').get());"
```

---

## 📊 Monitoring des Backups

### Vérifier le dernier backup

```bash
# Voir le dernier backup créé
ls -lt /var/backups/skinbaron/ | head -2

# Taille totale des backups
du -sh /var/backups/skinbaron/
```

### Alerting (avec Healthchecks.io - gratuit)

```bash
# Créer un check sur https://healthchecks.io
# UUID example: 1234abcd-5678-efgh-9012-ijklmnopqrst

# Modifier scripts/backup-db.sh pour ajouter à la fin :
# Ping Healthchecks.io pour confirmer le succès
curl -fsS -m 10 --retry 5 -o /dev/null \
  https://hc-ping.com/1234abcd-5678-efgh-9012-ijklmnopqrst
```

Si le backup échoue, Healthchecks.io t'envoie un email.

---

## 🔐 Chiffrement des Backups (Optionnel)

### Avec GPG

```bash
# Générer une clé GPG
gpg --gen-key

# Modifier scripts/backup-db.sh pour chiffrer :
gpg --encrypt --recipient your-email@example.com "$BACKUP_DIR/$BACKUP_FILE"
rm "$BACKUP_DIR/$BACKUP_FILE"  # Supprimer la version non chiffrée

# Restaurer :
gpg --decrypt /var/backups/skinbaron/alerts-20260113.tar.gz.gpg | \
  docker run --rm -i -v skinbaron_backend_data:/data alpine tar xz -C /data
```

---

## 📅 Politique de Rétention Recommandée

- **Quotidien** : 30 derniers jours (actuel)
- **Hebdomadaire** : 12 dernières semaines
- **Mensuel** : 12 derniers mois
- **Annuel** : 3 dernières années

Pour implémenter :
```bash
# Script avancé avec rotation
# 0 3 * * 0 ./scripts/backup-weekly.sh   # Dimanche
# 0 3 1 * * ./scripts/backup-monthly.sh  # 1er du mois
```

---

## ❓ FAQ

**Q: Combien d'espace disque nécessaire ?**  
R: ~200KB par backup quotidien = ~6MB/mois. Avec 30j de rétention : ~6MB total.

**Q: Impact performance du backup ?**  
R: Minimal (<1s), le container Alpine lit le volume en read-only.

**Q: Backup pendant que l'app tourne ?**  
R: Oui, SQLite gère le WAL mode, pas de corruption possible.

**Q: Tester sans écraser les données actuelles ?**  
R: Utiliser un volume temporaire :
```bash
docker volume create test_restore
docker run --rm -v test_restore:/data ...
docker volume rm test_restore
```
