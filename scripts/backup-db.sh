#!/bin/bash
# ================================
# SkinBaron Tracker - Backup Script
# ================================
# Sauvegarde quotidienne de la base de données SQLite
# Usage: ./scripts/backup-db.sh
# Cron: 0 3 * * * /path/to/backup-db.sh

set -e

# Configuration
VOLUME_NAME="skinbaron_backend_data"
BACKUP_DIR="/var/backups/skinbaron"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="alerts-${DATE}.tar.gz"
RETENTION_DAYS=30

# Couleurs pour les logs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Vérifier que le volume existe
if ! docker volume inspect "$VOLUME_NAME" &>/dev/null; then
    log_error "Volume $VOLUME_NAME n'existe pas !"
    exit 1
fi

# Créer le dossier de backup si nécessaire
log_info "Création du dossier de backup..."
mkdir -p "$BACKUP_DIR"

# Backup du volume Docker
log_info "Sauvegarde du volume $VOLUME_NAME..."
docker run --rm \
    -v "$VOLUME_NAME":/data:ro \
    -v "$BACKUP_DIR":/backup \
    alpine:latest \
    tar czf "/backup/$BACKUP_FILE" -C /data .

if [ $? -eq 0 ]; then
    BACKUP_SIZE=$(du -h "$BACKUP_DIR/$BACKUP_FILE" | cut -f1)
    log_info "✅ Backup créé : $BACKUP_FILE ($BACKUP_SIZE)"
else
    log_error "❌ Échec du backup !"
    exit 1
fi

# Nettoyage des anciens backups
log_info "Nettoyage des backups > $RETENTION_DAYS jours..."
DELETED=$(find "$BACKUP_DIR" -name "alerts-*.tar.gz" -type f -mtime +$RETENTION_DAYS -delete -print | wc -l)
if [ "$DELETED" -gt 0 ]; then
    log_info "🗑️  $DELETED ancien(s) backup(s) supprimé(s)"
fi

# Liste des backups disponibles
log_info "Backups disponibles :"
ls -lh "$BACKUP_DIR"/alerts-*.tar.gz 2>/dev/null | tail -5 || log_warn "Aucun backup trouvé"

log_info "✅ Backup terminé avec succès !"
