// get window thresholds based on observed margins
function windowThresholds(margins, releases) {
  const validMargins = margins.filter(m => Number.isFinite(m));
  const validReleases = releases.filter(v => v > 0);
  if (!validMargins.length || !validReleases.length) return {margin: 300, release: 0x2600};

  // compute as a *fraction* of best found margin/release to increase window reliability
  const bestMargin = Math.max(...validMargins);
  const bestRelease = Math.max(...validReleases);
  return {margin: Math.round(bestMargin * 0.75), release: Math.round(bestRelease * 0.8)};
}
module.exports = {windowThresholds};
