'use strict';
// TANPA DATABASE. Store ini hanya memori per-instance: dipakai untuk penghitung percobaan login (best effort) dan oleh tes.
// Tidak ada data penting yang bergantung padanya: admin, kunci Gemini, dan model berasal dari environment variable.
let mem = null;
async function store() {
  mem = mem || new Map();
  return {
    get: async k => (mem.has(k) ? JSON.parse(mem.get(k)) : null),
    set: async (k, v) => { mem.set(k, JSON.stringify(v)); },
    del: async k => { mem.delete(k); },
    list: async p => [...mem.keys()].filter(k => k.startsWith(p))
  };
}
// Penyimpanan tetap tidak ada di produksi, jadi panel Admin (kelola pengguna dan pengaturan yang disimpan) nonaktif.
// Hanya tes (ORBIT_MEMORY_DB=1) yang mensimulasikan penyimpanan tetap untuk menguji logika kelola pengguna.
const persistent = () => !!process.env.ORBIT_MEMORY_DB;
function resetMemory() { mem = null; }
module.exports = { store, persistent, resetMemory };
