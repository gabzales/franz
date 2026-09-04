// seed.js — Generate fake data untuk FranzzStore (topup game & premium app)
// Jalankan: node seed.js
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

// Bisa dioverride lewat env SEED_DB_PATH -- dipakai saat seed.js dipanggil
// dari route /admin/migrate-seed di Vercel, karena __dirname/database di
// Vercel itu read-only (bagian dari deployment bundle). Route itu set
// SEED_DB_PATH ke /tmp/database (satu-satunya folder writable di runtime
// serverless) sebelum require() file ini. Kalau dijalankan manual lewat
// `node seed.js` di lokal, env ini kosong -> tetap pakai ./database seperti biasa.
const dbPath = process.env.SEED_DB_PATH || path.join(__dirname, 'database');
if (!fs.existsSync(dbPath)) fs.mkdirSync(dbPath, { recursive: true });

const writeDB = (f, d) => fs.writeFileSync(path.join(dbPath, f), JSON.stringify(d, null, 2));
const readDB  = (f) => {
  const fp = path.join(dbPath, f);
  if (!fs.existsSync(fp)) return f.includes('settings') ? {} : [];
  try { return JSON.parse(fs.readFileSync(fp,'utf-8')); } catch { return []; }
};

const formatDate = (d = new Date()) => {
  const dt = new Date(d);
  const pad = n => String(n).padStart(2,'0');
  return `${pad(dt.getDate())}/${pad(dt.getMonth()+1)}/${dt.getFullYear()} ${pad(dt.getHours())}:${pad(dt.getMinutes())}`;
};

const avatarUrl = (seed) => `https://api.dicebear.com/7.x/pixel-art/png?seed=${encodeURIComponent(seed)}&size=80&backgroundColor=b6e3f4,c0aede,d1d4f9,ffd5dc,ffdfbf`;

// ─── 62 Fake Users ───
const userNames = [
  // Top buyers (banyak transaksi, semua punya foto)
  'FranzzPro','NightWolf','SkyyFire','DarkBlaze','LunarKing',
  'RedFalcon','IronPhoenix','ShadowX','NeonVibes','CyberRush',
  'AlphaGod','ZeroCool','PixelKnight','StormRider','GhostByte',
  // Mid buyers (foto campuran)
  'TurboAce','VoidBreaker','EchoStrike','FrostBite','MegaBoss',
  'QuantumZ','RiftWalker','BladeRunner','NovaStar','DragonByte',
  'PulseWave','HyperCore','OmegaX','CodeBreaker','StellarRift',
  // Buyers biasa (foto campuran)
  'FlashKing','CrimsonX','BlazeWolf','SilverBolt','TitanFury',
  'DuskReaper','NightHawk','PhantomEdge','SpeedDemon','IceFang',
  'ThunderGod','VenomShot','SkyWarden','DarkMatter','GoldRush',
  // Casual buyers (sebagian besar tanpa foto)
  'UserGaming88','Prayoga21','BudiSantoso','AndiKurniawan','RezaPlays',
  'FajarGamer','DoniPlayz','RizkiFF','HendriML','AgusTop',
  'SitiGamer','DewiPlays','NurulFF','RahmaFire','IndahGamers',
  // Inactive / 1-2 trx (kebanyakan tanpa foto)
  'NewPlayer01','Noob2024','Pemula99','GuestUser','TrialMode',
  'TestAcc01','RandomBuyer','OneTimeBuy','SilentUser','LurkerMode',
  'LastPlace61','LastPlace62'
];

// Index yang punya foto (40 dari 62)
const withPhoto = new Set([
  0,1,2,3,4,5,6,7,8,9,
  10,11,12,13,14,15,16,17,18,19,
  20,21,22,23,24,25,26,27,28,29,
  30,31,32,33,34,35,36,37,38,39,
  45,46,47,48,49
]);

const resellerIdx = new Set([0,1,2,5,14,30,33]);

const hashedPass = bcrypt.hashSync('password123', 10);
const now = Date.now();

const users = userNames.map((name, i) => {
  const id = uuidv4();
  const createdAt = new Date(now - (62-i) * 24*3600*1000 - Math.random()*7*24*3600*1000).toISOString();
  const isReseller = resellerIdx.has(i);
  return {
    id,
    username: name,
    password: hashedPass,
    wa: `0812${String(10000000 + i * 1234567 % 90000000).padStart(8,'0')}`,
    photo: withPhoto.has(i) ? avatarUrl(name) : null,
    createdAt,
    is_reseller: isReseller,
    role: isReseller ? 'reseller' : 'user',
    reseller_since: isReseller ? createdAt : undefined,
    reseller_code: isReseller ? `RSL-${name.slice(0,4).toUpperCase()}-${Math.random().toString(36).slice(2,6).toUpperCase()}` : undefined
  };
});

// ─── Produk Topup Game & Premium App ───
// Generator kode stok generik (tanpa tag durasi) — dipakai semua item.
const makeKeys = (prefix, count) => {
  const arr = [];
  for (let i = 1; i <= count; i++) {
    arr.push(`${prefix}-${String(i).padStart(3,'0')}`);
  }
  return arr;
};
// Catatan model data:
//  - `items`      : pilihan nominal/durasi yang tampil di halaman beli ({l: label, p: harga}).
//  - `pricingOptions`: pasangan (days, price) untuk matching order di server.
//    Untuk topup, "days" = nominal (mis. 70 = 70 diamond) — label bebas di `items.l`.
//    Untuk premium app, durasi ditulis "N HARI" di label biar ke-detect otomatis.
//  - `keys`       : stok kode generik (tanpa tag durasi "=") — dipakai untuk semua item.
const products = [
  {
    id: uuidv4(),
    name: 'FREE FIRE DIAMOND',
    category: 'freefire',
    description: 'Topup Diamond Free Fire langsung ke akun kamu via ID Player. Proses otomatis, legal, dan aman — diamond masuk dalam hitungan detik.',
    image: '/uploads/products/free-fire.png',
    items: [
      {l:'5 DIAMONDS',p:1000},
      {l:'12 DIAMONDS',p:2000},
      {l:'70 DIAMONDS',p:11000},
      {l:'140 DIAMONDS',p:21000},
      {l:'355 DIAMONDS',p:49000},
      {l:'720 DIAMONDS',p:96000},
      {l:'1450 DIAMONDS',p:185000},
      {l:'MEMBERSHIP MINGGUAN (7 HARI)',p:27000}
    ],
    keys: [...makeKeys('FFD',500)],
    requiresGameId: true, requiresZoneId: false, gameIdLabel: 'User ID', gameIdPlaceholder: 'Contoh: 123456789',
    status: 'active', sold: 1240, createdAt: new Date(now-90*86400000).toISOString()
  },
  {
    id: uuidv4(),
    name: 'MOBILE LEGENDS DIAMOND',
    category: 'mlbb',
    description: 'Topup Diamond Mobile Legends: Bang Bang via ID + Server. Proses instan, harga termurah, cocok buat beli skin & battle emote favoritmu.',
    image: '/uploads/products/mobile-legends.png',
    items: [
      {l:'78 DIAMONDS',p:19000},
      {l:'156 DIAMONDS',p:37000},
      {l:'344 DIAMONDS',p:79000},
      {l:'429 DIAMONDS',p:99000},
      {l:'875 DIAMONDS',p:199000},
      {l:'2010 DIAMONDS',p:445000},
      {l:'WEEKLY DIAMOND PASS (7 HARI)',p:28000}
    ],
    keys: [...makeKeys('MLD',500)],
    requiresGameId: true, requiresZoneId: true, gameIdLabel: 'User ID', gameIdPlaceholder: 'Contoh: 123456789', zoneIdLabel: 'Zone ID', zoneIdPlaceholder: 'Contoh: 1234',
    status: 'active', sold: 985, createdAt: new Date(now-85*86400000).toISOString()
  },
  {
    id: uuidv4(),
    name: 'PUBG MOBILE UC',
    category: 'pubgm',
    description: 'Topup UC PUBG Mobile via ID Player. Beli Royal Pass, skin, dan crate favoritmu. Proses cepat dan 100% aman.',
    image: '/uploads/products/pubg-mobile.png',
    items: [
      {l:'60 UC',p:13000},
      {l:'325 UC',p:65000},
      {l:'660 UC',p:130000},
      {l:'1800 UC',p:330000},
      {l:'3850 UC',p:660000},
      {l:'8100 UC',p:1320000}
    ],
    keys: [...makeKeys('PUC',400)],
    requiresGameId: true, requiresZoneId: false, gameIdLabel: 'Player ID', gameIdPlaceholder: 'Contoh: 512983xxxx',
    status: 'active', sold: 764, createdAt: new Date(now-80*86400000).toISOString()
  },
  {
    id: uuidv4(),
    name: 'GENSHIN IMPACT',
    category: 'genshin',
    description: 'Topup Genesis Crystal & Blessing of the Welkin Moon Genshin Impact via UID. Proses otomatis, support semua server (Asia, EU, US, TW/HK/MO).',
    image: '/uploads/products/genshin-impact.png',
    items: [
      {l:'60 GENESIS CRYSTALS',p:15000},
      {l:'330 GENESIS CRYSTALS',p:75000},
      {l:'1090 GENESIS CRYSTALS',p:235000},
      {l:'2240 GENESIS CRYSTALS',p:465000},
      {l:'3880 GENESIS CRYSTALS',p:780000},
      {l:'8080 GENESIS CRYSTALS',p:1550000},
      {l:'WELKIN MOON (30 HARI)',p:79000}
    ],
    keys: [...makeKeys('GIC',300)],
    requiresGameId: true, requiresZoneId: false, gameIdLabel: 'UID', gameIdPlaceholder: 'Contoh: 812345678',
    status: 'active', sold: 512, createdAt: new Date(now-75*86400000).toISOString()
  },
  {
    id: uuidv4(),
    name: 'VALORANT POINT',
    category: 'valorant',
    description: 'Topup Valorant Point (VP) via Riot ID. Beli skin bundle & battle pass favoritmu. Proses cepat, harga di bawah harga in-game.',
    image: '/uploads/products/valorant.png',
    items: [
      {l:'400 VP',p:45000},
      {l:'800 VP',p:90000},
      {l:'1600 VP',p:175000},
      {l:'2400 VP',p:260000},
      {l:'4000 VP',p:425000}
    ],
    keys: [...makeKeys('VPT',300)],
    requiresGameId: true, requiresZoneId: false, gameIdLabel: 'Riot ID', gameIdPlaceholder: 'Contoh: NamaKamu#1234',
    status: 'active', sold: 341, createdAt: new Date(now-70*86400000).toISOString()
  },
  {
    id: uuidv4(),
    name: 'SPOTIFY PREMIUM',
    category: 'premium',
    description: 'Spotify Premium Individu — bebas iklan, download offline, kualitas audio terbaik. Akun sendiri (bukan sharing), garansi penuh selama masa aktif.',
    image: '/uploads/products/spotify.png',
    items: [
      {l:'INDIVIDU 30 HARI',p:25000},
      {l:'INDIVIDU 90 HARI',p:65000},
      {l:'INDIVIDU 365 HARI',p:199000}
    ],
    keys: [...makeKeys('SPT',200)],
    status: 'active', sold: 876, createdAt: new Date(now-60*86400000).toISOString()
  },
  {
    id: uuidv4(),
    name: 'YOUTUBE PREMIUM',
    category: 'premium',
    description: 'YouTube Premium + YouTube Music — bebas iklan, play background, dan download offline. Garansi penuh selama masa aktif.',
    image: '/uploads/products/youtube.png',
    items: [
      {l:'30 HARI',p:15000},
      {l:'90 HARI',p:39000},
      {l:'365 HARI',p:129000}
    ],
    keys: [...makeKeys('YTP',200)],
    status: 'active', sold: 654, createdAt: new Date(now-55*86400000).toISOString()
  },
  {
    id: uuidv4(),
    name: 'NETFLIX PREMIUM',
    category: 'premium',
    description: 'Netflix Premium — profil private (bukan sharing), kualitas 4K UHD, bebas ganti perangkat. Garansi replace selama masa aktif.',
    image: '/uploads/products/netflix.png',
    items: [
      {l:'SHARING 30 HARI',p:45000},
      {l:'PRIVATE 30 HARI',p:120000}
    ],
    keys: [...makeKeys('NFL',150)],
    status: 'active', sold: 445, createdAt: new Date(now-50*86400000).toISOString()
  },
  {
    id: uuidv4(),
    name: 'CANVA PRO',
    category: 'premium',
    description: 'Canva Pro member invite — unlock semua template premium, background remover, 1TB storage. Garansi penuh selama masa aktif.',
    image: '/uploads/products/canva.png',
    items: [
      {l:'30 HARI',p:10000},
      {l:'365 HARI',p:35000}
    ],
    keys: [...makeKeys('CNV',200)],
    status: 'active', sold: 720, createdAt: new Date(now-45*86400000).toISOString()
  },
  {
    id: uuidv4(),
    name: 'CAPCUT PRO',
    category: 'premium',
    description: 'CapCut Pro — bebas watermark, efek & template premium eksklusif, export kualitas maksimal. Garansi penuh selama masa aktif.',
    image: '/uploads/products/capcut.png',
    items: [
      {l:'30 HARI',p:35000}
    ],
    keys: [...makeKeys('CCP',150)],
    status: 'active', sold: 389, createdAt: new Date(now-40*86400000).toISOString()
  },
  {
    id: uuidv4(),
    name: 'DISNEY+ HOTSTAR',
    category: 'premium',
    description: 'Disney+ Hotstar Premium — nonton film, series, dan olahraga (MPL, Premier League) kualitas 4K. Garansi replace selama masa aktif.',
    image: '/uploads/products/disneyplus.png',
    items: [
      {l:'30 HARI',p:35000},
      {l:'365 HARI',p:199000}
    ],
    keys: [...makeKeys('DNP',150)],
    status: 'active', sold: 298, createdAt: new Date(now-35*86400000).toISOString()
  }
];

// ─── Transaksi — distribusi realistis untuk 62 users ───
// Top 15: banyak banget, mid 25: sedang, sisa: sedikit
const trxCounts = [
  // index 0-14: top buyers
  45, 38, 33, 28, 25, 22, 20, 18, 16, 15,
  14, 13, 12, 11, 10,
  // index 15-29: mid buyers
  9, 9, 8, 8, 7, 7, 6, 6, 5, 5,
  5, 4, 4, 4, 3,
  // index 30-44: regular
  8, 7, 6, 6, 5, 5, 4, 4, 3, 3,
  3, 2, 2, 2, 2,
  // index 45-61: casual / inactive
  4, 3, 3, 2, 2,
  1, 1, 1, 1, 1,
  1, 1, 1, 1, 1,
  1, 1
];

const doneRatio = 0.88;
const transactions = [];
const orderChars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const genCode = () => {
  let c = 'GP-';
  for (let i=0;i<4;i++) c += orderChars[Math.floor(Math.random()*orderChars.length)];
  c += '-';
  for (let i=0;i<4;i++) c += orderChars[Math.floor(Math.random()*orderChars.length)];
  return c;
};

let keyCounter = {};
const getKey = (product, days) => {
  const k = `${product.id}:${days}`;
  if (!keyCounter[k]) keyCounter[k] = 0;
  keyCounter[k]++;
  const prefix = product.name.slice(0,2).toUpperCase().replace(/\s/,'');
  return `${prefix}${days}-${String(keyCounter[k]).padStart(3,'0')}`;
};

users.forEach((user, ui) => {
  const count = trxCounts[ui] || 0;
  for (let t = 0; t < count; t++) {
    const product = products[Math.floor(Math.random() * products.length)];
    const item = product.items[Math.floor(Math.random() * product.items.length)];
    const m = (item.l.match(/(\d+)/)||[]);
    const days = m[1] ? parseInt(m[1]) : 7;
    const isDone = Math.random() < doneRatio;
    const basePrice = item.p;
    const price = user.is_reseller ? Math.round(basePrice * 0.8) : basePrice;
    const daysAgo = Math.floor(Math.random() * 60) + 1;
    const trxDate = new Date(now - daysAgo*86400000 - Math.random()*43200000);

    transactions.push({
      id: uuidv4(),
      orderId: `GP-${trxDate.getTime()}`,
      code: genCode(),
      userId: user.id,
      productId: product.id,
      productName: product.name,
      duration: item.l,
      selectedDays: days,
      price,
      totalPayment: price,
      customerName: user.username,
      wa: user.wa,
      qrString: null,
      isStatic: true,
      status: isDone ? 'done' : (Math.random() < 0.5 ? 'pending' : 'expired'),
      key: isDone ? getKey(product, days) : null,
      paidAt: isDone ? trxDate.toISOString() : null,
      createdAt: trxDate.toISOString(),
      time: formatDate(trxDate)
    });
  }
});

transactions.sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt));

// ─── Testimonials (50 fake reviews) ───
const reviewTexts = [
  'Topup diamond masuk kurang dari 1 menit, prosesnya otomatis. Mantap!',
  'Harga paling murah se-Indonesia, udah bandingkan sama toko lain.',
  'Legit! Baru bayar QRIS, diamond langsung masuk ke akun.',
  'Admin ramah dan fast respon, topup di sini langganan terus.',
  'Spotify Premium-nya original, garansi penuh. Recommended!',
  'Udah langganan bulanan di sini, gak pernah ada masalah.',
  'Proses cepet banget, tinggal isi ID game langsung jalan.',
  'Toko terpercaya, udah banyak transaksi gak ada kendala sama sekali.',
  'YouTube Premium-nya masih aktif sampai sekarang, worth it banget!',
  'Harga bersahabat buat pelajar, prosesnya juga gak ribet.',
  'Topup UC langsung masuk, gak pake nunggu lama. GG!',
  'Pelayanan 10/10, salah isi ID dibantu cepat sama admin.',
  'Canva Pro-nya work terus, harga murah banget dibanding langganan resmi.',
  'Pertama kali topup di sini dan langsung sukses. No cap!',
  'Diamond FF murah, proses instan, admin fast respon. Mantul!',
  'Netflix Premium-nya private bukan sharing, kualitas 4K jalan terus.',
  'Langganan di sini dari dulu, gak pernah zonk. Terpercaya!',
  'Pembayaran QRIS gampang, pesanan langsung diproses otomatis.',
  'Welkin Genshin cuma 79rb, lebih murah dari harga resmi.',
  'Repeat order ke-5 kalinya, tetap lancar semua. Recommended parah!',
  'Teman-teman satu squad semua topup di sini, murah dan aman.',
  'CapCut Pro-nya langsung aktif di akun, prosesnya cepet banget.',
  'Awalnya ragu, ternyata legit. Bakal order lagi sih ini.',
  'MLBB diamond masuk bahkan belum sampai 1 menit. Gila sih.',
  'Harga termurah yang ada, kualitas tetap premium.',
  'CS-nya sabar banget jawab pertanyaan, top markotop!',
  'Disney+ Hotstar 1 tahun cuma segitu? Worth it banget!',
  'Transaksi aman, privasi data akun dijaga. Aman poll!',
  'Topup tengah malam pun prosesnya tetap otomatis jalan. Recommended!',
  'Valorant Point masuk langsung, harga lebih murah dari in-game.'
];

const testimonials = [];
for (let i = 0; i < 50; i++) {
  const user = users[Math.floor(Math.random() * 40)];
  const product = products[Math.floor(Math.random() * products.length)];
  const rating = Math.random() < 0.65 ? 5 : (Math.random() < 0.6 ? 4 : 3);
  const daysAgo = Math.floor(Math.random() * 45) + 1;
  testimonials.push({
    id: uuidv4(),
    product: product.name,
    productName: product.name,
    username: user.username,
    name: user.username,
    photo: user.photo || null,
    rating,
    text: reviewTexts[i % reviewTexts.length],
    date: new Date(now - daysAgo * 86400000).toISOString(),
    verified: Math.random() < 0.75,
    featured: Math.random() < 0.40
  });
}

// ─── Notifications ───
const notifications = transactions
  .filter(t => t.status === 'done')
  .slice(0, 80)
  .map(t => {
    const buyer = users.find(u => u.id === t.userId);
    return {
      id: uuidv4(),
      type: 'purchase',
      buyerName: t.customerName,
      buyerPhoto: buyer?.photo || null,
      productName: t.productName,
      price: t.price,
      time: t.paidAt,
      timeStr: formatDate(t.paidAt)
    };
  });

// ─── Write semua ke database ───
writeDB('users.json', users);
writeDB('products.json', products);
writeDB('transactions.json', transactions);
writeDB('testimonials.json', testimonials);
writeDB('notifications.json', notifications);

const settings = readDB('settings.json');
settings.categories = ['freefire','mlbb','pubgm','genshin','valorant','premium'];
settings.categoryLabels = {
  freefire: 'FREE FIRE',
  mlbb: 'MOBILE LEGENDS',
  pubgm: 'PUBG MOBILE',
  genshin: 'GENSHIN IMPACT',
  valorant: 'VALORANT',
  premium: 'PREMIUM APP'
};
settings.resellerEnabled = true;
settings.resellerPrice = 50000;
settings.resellerDiscount = 20;
settings.resellerNote = 'Dapatkan diskon eksklusif 20% untuk semua produk!';
writeDB('settings.json', settings);

// ─── Summary ───
const doneTrx = transactions.filter(t=>t.status==='done');
console.log('\n✅ Seed data berhasil dibuat!\n');
console.log(`👥 Users       : ${users.length} (${users.filter(u=>u.photo).length} dengan foto, ${users.filter(u=>!u.photo).length} tanpa foto, ${users.filter(u=>u.is_reseller).length} reseller)`);
console.log(`📦 Products    : ${products.length}`);
console.log(`💳 Transactions: ${transactions.length} (${doneTrx.length} done, ${transactions.filter(t=>t.status==='pending').length} pending)`);
console.log(`⭐ Testimonials : ${testimonials.length} (${testimonials.filter(t=>t.featured).length} featured)`);
console.log(`🔔 Notifications: ${notifications.length}`);
console.log('\n');
