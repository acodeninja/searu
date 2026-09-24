const int = (value, fallback) => {
  const parsed = Number.parseInt(value ?? '', 10);
  return Number.isNaN(parsed) ? fallback : parsed;
};

export const config = {
  port: int(process.env.PORT, 8080),
  publicDir: process.env.PUBLIC_DIR ?? 'public',
  jwtSecret: process.env.JWT_SECRET ?? 'sife-signing-key',
  sessionSecret: process.env.SESSION_SECRET ?? 'sife-session',
  shareKey: process.env.SHARE_KEY ?? 'sife-share-key01',
  exportKey: process.env.EXPORT_KEY ?? 'sife-export-key-0123456789abcdef',
  postgres: {
    host: process.env.PGHOST ?? 'localhost',
    port: int(process.env.PGPORT, 5432),
    user: process.env.PGUSER ?? 'sife',
    password: process.env.PGPASSWORD ?? 'sife',
    database: process.env.PGDATABASE ?? 'sife',
  },
  mongo: {
    url: process.env.MONGO_URL ?? 'mongodb://localhost:27017',
    database: process.env.MONGO_DB ?? 'sife',
  },
};
