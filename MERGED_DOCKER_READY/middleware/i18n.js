const fs = require('fs');
const path = require('path');

module.exports = function i18n(){
  const localesDir = path.join(process.cwd(), 'locales');
  const cache = {};
  function load(lang){
    if(cache[lang]) return cache[lang];
    try{
      cache[lang] = JSON.parse(fs.readFileSync(path.join(localesDir, lang + '.json'),'utf-8'));
    }catch(e){ cache[lang] = {}; }
    return cache[lang];
  }
  return function(req,res,next){
    const lang = (req.query.lang || req.cookies?.lang || process.env.DEFAULT_LANG || 'en').toLowerCase();
    const dict = load(lang);
    res.locals.t = (k)=> dict[k] || null;
    next();
  }
}
