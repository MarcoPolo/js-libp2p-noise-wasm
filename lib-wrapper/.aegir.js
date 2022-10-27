import { spawn, exec } from "child_process";
import { existsSync } from "fs";

/** @type {import('aegir/types').PartialOptions} */
export default {
  test: {
  },
  build: {
    bundlesizeMax: '18kB'
  }
}
