# Bundled browser dependencies

- `capstone.min.js` is the legacy [Capstone.js](https://github.com/AlexAltea/capstone.js) decoder used only for v1 traces, which do not embed disassembly. The Capstone.js and Capstone BSD notices are retained as `capstone-js.LICENSE` and `capstone.LICENSE`.
- `dagre.min.js` is the unmodified browser distribution of [Dagre 1.1.5](https://github.com/dagrejs/dagre/tree/v1.1.5), including Graphlib. Both MIT notices are retained as `dagre.LICENSE` and `graphlib.LICENSE`. Refresh it with `pnpm run vendor:cfg` after installing the locked development dependencies.

These files keep the standalone viewer functional over `file://`; it never fetches code from a CDN.
