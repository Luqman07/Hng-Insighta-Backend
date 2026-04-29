// Country name → ISO code map for NLP parsing
const COUNTRY_MAP = {
  nigeria: "NG", ghana: "GH", kenya: "KE", tanzania: "TZ", uganda: "UG",
  ethiopia: "ET", cameroon: "CM", senegal: "SN", angola: "AO", zambia: "ZM",
  zimbabwe: "ZW", mozambique: "MZ", madagascar: "MG", mali: "ML", niger: "NE",
  "burkina faso": "BF", guinea: "GN", benin: "BJ", togo: "TG", rwanda: "RW",
  somalia: "SO", sudan: "SD", egypt: "EG", morocco: "MA", algeria: "DZ",
  tunisia: "TN", libya: "LY", "south africa": "ZA", namibia: "NA", botswana: "BW",
  malawi: "MW", "ivory coast": "CI", "cote d'ivoire": "CI", liberia: "LR",
  "sierra leone": "SL", gambia: "GM", "guinea-bissau": "GW", "cape verde": "CV",
  mauritania: "MR", chad: "TD", "central african republic": "CF", gabon: "GA",
  congo: "CG", "democratic republic of congo": "CD", burundi: "BI",
  eritrea: "ER", djibouti: "DJ", comoros: "KM", "sao tome": "ST",
  equatorial: "GQ", lesotho: "LS", swaziland: "SZ", eswatini: "SZ",
  seychelles: "SC", mauritius: "MU",
};

function parseNaturalLanguage(q) {
  const text = q.toLowerCase();
  const filters = {};
  let matched = false;

  if (/\bmales?\b/.test(text) && !/\bfemales?\b/.test(text)) {
    filters.gender = "male"; matched = true;
  } else if (/\bfemales?\b/.test(text) && !/\bmales?\b/.test(text)) {
    filters.gender = "female"; matched = true;
  } else if (/\b(male and female|female and male|people|persons|individuals)\b/.test(text)) {
    matched = true;
  }

  if (/\bchildren\b|\bchild\b/.test(text)) {
    filters.age_group = "child"; matched = true;
  } else if (/\bteenagers?\b/.test(text)) {
    filters.age_group = "teenager"; matched = true;
  } else if (/\badults?\b/.test(text)) {
    filters.age_group = "adult"; matched = true;
  } else if (/\bseniors?\b|\belderly\b/.test(text)) {
    filters.age_group = "senior"; matched = true;
  } else if (/\byoung\b/.test(text)) {
    filters.min_age = 16; filters.max_age = 24; matched = true;
  }

  const aboveMatch = text.match(/\babove\s+(\d+)\b/);
  const belowMatch = text.match(/\bbelow\s+(\d+)\b/);
  const olderMatch = text.match(/\bolder\s+than\s+(\d+)\b/);
  const youngerMatch = text.match(/\byounger\s+than\s+(\d+)\b/);
  const betweenMatch = text.match(/\bbetween\s+(\d+)\s+and\s+(\d+)\b/);

  if (aboveMatch) { filters.min_age = parseInt(aboveMatch[1]); matched = true; }
  if (olderMatch) { filters.min_age = parseInt(olderMatch[1]); matched = true; }
  if (belowMatch) { filters.max_age = parseInt(belowMatch[1]); matched = true; }
  if (youngerMatch) { filters.max_age = parseInt(youngerMatch[1]); matched = true; }
  if (betweenMatch) {
    filters.min_age = parseInt(betweenMatch[1]);
    filters.max_age = parseInt(betweenMatch[2]);
    matched = true;
  }

  const fromMatch = text.match(/\bfrom\s+([a-z\s'-]+?)(?:\s+(?:above|below|older|younger|between|aged|who|with|and|$))/);
  const inMatch = text.match(/\bin\s+([a-z\s'-]+?)(?:\s+(?:above|below|older|younger|between|aged|who|with|and|$))/);
  const countryPhrase = (fromMatch && fromMatch[1].trim()) || (inMatch && inMatch[1].trim());

  if (countryPhrase) {
    const code = COUNTRY_MAP[countryPhrase];
    if (code) {
      filters.country_id = code; matched = true;
    } else {
      for (const word of countryPhrase.split(/\s+/)) {
        if (COUNTRY_MAP[word]) { filters.country_id = COUNTRY_MAP[word]; matched = true; break; }
      }
    }
  }

  if (!matched) return null;
  return filters;
}

module.exports = { parseNaturalLanguage };
