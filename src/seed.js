const Database = require("better-sqlite3");
const { v7: uuidv7 } = require("uuid");
const path = require("path");
const fs = require("fs");

const seedFile = process.argv[2] || path.join(__dirname, "..", "seed_profiles.json");

if (!fs.existsSync(seedFile)) {
  console.error(`Seed file not found: ${seedFile}`);
  console.error("Usage: node src/seed.js [path/to/seed_profiles.json]");
  process.exit(1);
}

const db = new Database(path.join(__dirname, "..", "db.sqlite"));

db.exec(`
  CREATE TABLE IF NOT EXISTS profiles (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE,
    gender TEXT,
    gender_probability REAL,
    age INTEGER,
    age_group TEXT,
    country_id TEXT,
    country_name TEXT,
    country_probability REAL,
    created_at TEXT
  )
`);

const { profiles } = JSON.parse(fs.readFileSync(seedFile, "utf-8"));

const insert = db.prepare(`
  INSERT OR IGNORE INTO profiles
    (id, name, gender, gender_probability, age, age_group, country_id, country_name, country_probability, created_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const seedMany = db.transaction((records) => {
  let inserted = 0;
  for (const p of records) {
    const result = insert.run(uuidv7(), p.name, p.gender, p.gender_probability, p.age, p.age_group, p.country_id, p.country_name || "", p.country_probability, new Date().toISOString());
    if (result.changes > 0) inserted++;
  }
  return inserted;
});

const inserted = seedMany(profiles);
console.log(`Seeded ${inserted} new profiles (${profiles.length - inserted} already existed).`);
db.close();
