// entryMarker.ts — proof that the app, and not the library, is what Electron
// was pointed at.
//
// package.json's "main" is `src/core/index.ts`, which is correct for an npm
// dependency and is ALSO the field Electron reads to find an app's entry point.
// So `electron .` loads the library: no window, no error, and a live process
// that is indistinguishable from a launch that silently failed. That cost a
// whole session of debugging a palette in an app that was never running.
//
// core/index.ts refuses to be an Electron entry point, and this is how it can
// tell the difference between "I am the entry" and "the entry imported me".
// ES modules evaluate their imports in source order, depth first, so a marker
// imported ABOVE the core import is guaranteed to have run before core's body
// does. Nothing else about the two cases differs: process.type is 'browser'
// either way, and process.argv[1] is a path the packaged build would not have.
//
// This import must stay first in main.ts. That is the whole contract.

declare global {
  // eslint-disable-next-line no-var
  var __bashmeAppEntry: boolean | undefined;
}

globalThis.__bashmeAppEntry = true;

export {};
