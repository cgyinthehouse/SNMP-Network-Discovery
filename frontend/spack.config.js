const { config } = require("@swc/core/spack");

module.exports = config({
  entry: {
    main: __dirname + "/src/app.ts",
  },
  output: {
    path: __dirname + "/static/js",
    name: "app.js",
  }
});
