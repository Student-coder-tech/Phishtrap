import { rmSync, mkdirSync, readdirSync, statSync, copyFileSync } from "fs";
import { join } from "path";

function copyDir(src, dest) {
  mkdirSync(dest, { recursive: true });
  for (const entry of readdirSync(src)) {
    const srcPath = join(src, entry);
    const destPath = join(dest, entry);
    if (statSync(srcPath).isDirectory()) {
      copyDir(srcPath, destPath);
    } else {
      copyFileSync(srcPath, destPath);
    }
  }
}

rmSync("dist", { recursive: true, force: true });
copyDir("client/dist", "dist");
console.log("Copied client/dist -> dist/");
