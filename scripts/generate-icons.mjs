import { readFile, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { Resvg } from "@resvg/resvg-js";

const SIZES = [16, 32, 48, 128];

export const generateIcons = async ({ distDir }) => {
  const svgPath = path.join(process.cwd(), "src", "static", "icon.svg");
  const svg = await readFile(svgPath, "utf8");

  const iconsDir = path.join(distDir, "icons");
  await mkdir(iconsDir, { recursive: true });

  for (const size of SIZES) {
    const resvg = new Resvg(svg, {
      fitTo: {
        mode: "width",
        value: size
      }
    });
    const png = resvg.render().asPng();
    await writeFile(path.join(iconsDir, `icon${size}.png`), png);
  }
};
