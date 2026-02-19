import '@testing-library/jest-dom';
// Additional global test setup can go here (e.g., mock fetch, global CSS resets)

// Ensure tests have a valid document title and html lang to satisfy accessibility checks
document.title = 'Vigilant Canary — Dashboard';
document.documentElement.lang = 'en';

// Polyfill minimal canvas API for jsdom to avoid "getContext not implemented" warnings
// Used by libraries like html2canvas / jspdf during tests
if (typeof HTMLCanvasElement !== 'undefined' && !HTMLCanvasElement.prototype.getContext) {
  // @ts-ignore - augment prototype in test environment
  HTMLCanvasElement.prototype.getContext = function () {
    return {
      fillRect: () => {},
      clearRect: () => {},
      getImageData: (_x: number, _y: number, w: number, h: number) => ({ data: new Array(w * h * 4) }),
      putImageData: () => {},
      createImageData: () => ([]),
      setTransform: () => {},
      drawImage: () => {},
      save: () => {},
      restore: () => {},
      beginPath: () => {},
      moveTo: () => {},
      lineTo: () => {},
      closePath: () => {},
      stroke: () => {},
      fillText: () => {},
      measureText: () => ({ width: 0 }),
      toDataURL: () => ''
    } as any;
  };
}

// Suppress jsdom's canvas getContext console message in tests
const _origConsoleError = console.error.bind(console);
console.error = (...args: any[]) => {
  const msg = args?.[0];
  if (typeof msg === 'string' && msg.includes("HTMLCanvasElement's getContext() method")) {
    return;
  }
  _origConsoleError(...args);
};
