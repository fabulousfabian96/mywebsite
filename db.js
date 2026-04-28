const path = require('path');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');

async function openDatabase() {
  return open({
    filename: path.join(__dirname, 'kabianga.db'),
    driver: sqlite3.Database
  });
}

module.exports = { openDatabase };
