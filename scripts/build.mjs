import { build } from "esbuild";
import { cp, mkdir, rm } from "node:fs/promises";
import path from "node:path";
import { generateIcons } from "./generate-icons.mjs";

const root = process.cwd();
const distDir = path.join(root, "dist");

await rm(distDir, { recursive: true, force: true });
await mkdir(distDir, { recursive: true });

await generateIcons({ distDir });

const common = {
  bundle: true,
  target: "chrome120",
  format: "iife",
  sourcemap: true,
  logLevel: "info"
};

await Promise.all([
  build({
    ...common,
    format: "esm",
    entryPoints: { background: "src/background/index.ts" },
    outdir: distDir
  }),
  build({
    ...common,
    entryPoints: { devtools: "src/devtools/index.ts" },
    outdir: distDir
  }),
  build({
    ...common,
    entryPoints: { content: "src/content/index.ts" },
    outdir: distDir
  }),
  build({
    ...common,
    entryPoints: { panel: "src/panel/main.tsx" },
    outdir: distDir
  }),
  build({
    ...common,
    entryPoints: { sidepanel: "src/sidepanel/main.tsx" },
    outdir: distDir
  })
]);

await Promise.all([
  cp("src/static/manifest.json", path.join(distDir, "manifest.json")),
  cp("src/static/devtools.html", path.join(distDir, "devtools.html")),
  cp("src/static/panel.html", path.join(distDir, "panel.html")),
  cp("src/static/sidepanel.html", path.join(distDir, "sidepanel.html")),
  cp("src/panel/styles.css", path.join(distDir, "styles.css"))
]);
