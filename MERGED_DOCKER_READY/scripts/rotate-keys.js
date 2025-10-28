#!/usr/bin/env node
const { rotate } = require('../utils/keys');
const out = rotate();
console.log('Rotated key:', out);
