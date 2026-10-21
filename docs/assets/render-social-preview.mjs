// Render docs/assets/social-preview.html -> social-preview.png (1280x640) for the
// GitHub social preview (Settings -> General -> Social preview).
// Needs Node + playwright; set CHROMIUM_PATH to use a local Chromium build.
import { chromium } from "playwright";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const browser = await chromium.launch(
  process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {}
);
const page = await browser.newPage({ viewport: { width: 1280, height: 640 } });
await page.goto(pathToFileURL(path.join(here, "social-preview.html")).href);
await page.screenshot({ path: path.join(here, "social-preview.png") });
await browser.close();
console.log("wrote", path.join(here, "social-preview.png"));
