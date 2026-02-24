/**
 * Configuración de variables de entorno para tests.
 * Este archivo se ejecuta ANTES de que se carguen los módulos del proyecto
 * gracias a la configuración `setupFiles` en jest (package.json).
 */

// Base de datos en memoria para tests — cada worker de Jest tiene la suya
process.env['DATABASE_PATH'] = ':memory:';
process.env['NODE_ENV'] = 'test';

// JWT secret de test (mínimo 32 chars)
process.env['JWT_SECRET'] = 'test-secret-key-de-test-para-jest-32chars-ok';
process.env['JWT_EXPIRY_ACCESS'] = '15m';
process.env['JWT_EXPIRY_REFRESH'] = '7d';

// IP hash salt de test
process.env['IP_HASH_SALT'] = 'test-salt-para-hashing-de-ips-16c';

// Frontend URL
process.env['FRONTEND_URL'] = 'http://localhost:3000';

// Puerto para tests — supertest usa request(app) que no depende de este puerto
process.env['PORT'] = '4999';

// OAuth — valores vacíos para no requerir configuración real
process.env['GITHUB_CLIENT_ID'] = '';
process.env['GITHUB_CLIENT_SECRET'] = '';
process.env['GITHUB_CALLBACK_URL'] = 'http://localhost:3000/api/v1/oauth/github/callback';
process.env['GOOGLE_CLIENT_ID'] = '';
process.env['GOOGLE_CLIENT_SECRET'] = '';
process.env['GOOGLE_CALLBACK_URL'] = 'http://localhost:3000/api/v1/oauth/google/callback';
process.env['M2M_CLIENT_ID'] = 'test-m2m-client';
process.env['M2M_CLIENT_SECRET'] = 'test-m2m-secret-seguro-1234567890';

// Email — deshabilitado en tests
process.env['GMAIL_USER'] = '';
process.env['GMAIL_APP_PASSWORD'] = '';

// PASETO — se generarán efímeras
process.env['PASETO_PRIVATE_KEY'] = '';
process.env['PASETO_PUBLIC_KEY'] = '';
