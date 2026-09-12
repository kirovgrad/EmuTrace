/* Refresh the offline graph-layout bundle from the locked npm dependencies. */
const fs = require("node:fs");
const path = require("node:path");
const root = path.resolve(__dirname, "..");
const dagre = path.dirname(require.resolve("@dagrejs/dagre/package.json"));
const graphlib = path.dirname(
  require.resolve("@dagrejs/graphlib/package.json", { paths: [dagre] }),
);
fs.mkdirSync(path.join(root, "vendor"), { recursive: true });
for (const [source, destination] of [
  [path.join(dagre, "dist/dagre.min.js"), "dagre.min.js"],
  [path.join(dagre, "LICENSE"), "dagre.LICENSE"],
  [path.join(graphlib, "LICENSE"), "graphlib.LICENSE"],
])
  fs.copyFileSync(source, path.join(root, "vendor", destination));
