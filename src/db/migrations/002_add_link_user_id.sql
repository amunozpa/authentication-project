-- Fase 5.9: Account Linking Dashboard
-- Añade columna link_user_id a oauth_states para distinguir flujos
-- de vinculación (usuario ya autenticado) de flujos de login.
-- Si es NULL → flujo de login/registro normal.
-- Si tiene valor → flujo de vinculación: el userId del usuario autenticado.
ALTER TABLE oauth_states ADD COLUMN link_user_id TEXT DEFAULT NULL;
