/**
 * Inicialización de base de datos SQLite — Fase 2
 * Sistema de migraciones secuenciales.
 * Cada migración se aplica una sola vez y queda registrada en _migrations.
 */
import Database, { type Database as DatabaseType } from 'better-sqlite3';
import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';
import { logger } from '../logger';

// En Docker, montar el volumen en /data y configurar DATABASE_PATH=/data/database.sqlite
const DB_PATH = process.env['DATABASE_PATH'] ?? './database.sqlite';

export const db: DatabaseType = new Database(DB_PATH);

// ── Pragmas de rendimiento y seguridad ───────────────────────
// WAL: Write-Ahead Logging — mayor concurrencia de lecturas
db.pragma('journal_mode = WAL');
// Integridad referencial (SQLite la deshabilita por defecto)
db.pragma('foreign_keys = ON');
// Balance seguridad/rendimiento (FULL=seguro, OFF=rápido, NORMAL=intermedio)
db.pragma('synchronous = NORMAL');
// Tamaño de caché en páginas de 4KB (4MB total)
db.pragma('cache_size = -4000');

// ── Sistema de migraciones ────────────────────────────────────
function runMigrations(): void {
  // Tabla de control de migraciones — siempre debe existir primero
  db.exec(`
    CREATE TABLE IF NOT EXISTS _migrations (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      name       TEXT UNIQUE NOT NULL,
      applied_at INTEGER NOT NULL
    )
  `);

  const migrationsDir = join(__dirname, 'migrations');

  // Leer archivos .sql ordenados alfabéticamente (001_, 002_, ...)
  let files: string[];
  try {
    files = readdirSync(migrationsDir)
      .filter((f) => f.endsWith('.sql'))
      .sort();
  } catch {
    logger.warn('Directorio de migraciones no encontrado — no se aplicaron migraciones');
    return;
  }

  const checkApplied = db.prepare<[string], { name: string }>(
    'SELECT name FROM _migrations WHERE name = ?',
  );
  const recordApplied = db.prepare(
    'INSERT INTO _migrations (name, applied_at) VALUES (?, ?)',
  );

  for (const file of files) {
    const row = checkApplied.get(file);
    if (row) continue; // ya aplicada

    logger.info(`Aplicando migración: ${file}`);
    const sql = readFileSync(join(migrationsDir, file), 'utf-8');
    db.exec(sql);
    recordApplied.run(file, Date.now());
    logger.info(`Migración aplicada correctamente: ${file}`);
  }
}

runMigrations();
logger.info(`Base de datos inicializada: ${DB_PATH}`);
