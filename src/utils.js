function getAgeGroup(age) {
  if (age === null || age === undefined) return null;
  if (age <= 12) return "child";
  if (age <= 19) return "teenager";
  if (age <= 59) return "adult";
  return "senior";
}

function fetchDataFromAPIs(name) {
  return Promise.all([
    fetch(`https://api.genderize.io?name=${encodeURIComponent(name)}`),
    fetch(`https://api.agify.io?name=${encodeURIComponent(name)}`),
    fetch(`https://api.nationalize.io?name=${encodeURIComponent(name)}`),
  ]).then(([g, a, c]) => {
    if (!g.ok) throw new Error("Genderize API failed");
    if (!a.ok) throw new Error("Agify API failed");
    if (!c.ok) throw new Error("Nationalize API failed");
    return Promise.all([g.json(), a.json(), c.json()]);
  });
}

module.exports = { getAgeGroup, fetchDataFromAPIs };
