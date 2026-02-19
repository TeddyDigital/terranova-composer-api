require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

const {
  SHOPIFY_API_KEY,
  SHOPIFY_API_SECRET,
  SHOPIFY_STORE,
  SHOPIFY_ACCESS_TOKEN,
  APP_URL,
  PORT = 3001
} = process.env;

// File per salvare il token persistente
const TOKEN_FILE = path.join(__dirname, '.token');

// Margine di sicurezza per il refresh (5 minuti prima della scadenza)
const REFRESH_MARGIN_MS = 5 * 60 * 1000;

// Legge i dati del token dal file
function getStoredTokenData() {
  try {
    if (fs.existsSync(TOKEN_FILE)) {
      const content = fs.readFileSync(TOKEN_FILE, 'utf8').trim();
      // Prova a parsare come JSON (nuovo formato)
      try {
        return JSON.parse(content);
      } catch {
        // Fallback: vecchio formato (solo access_token come stringa)
        return { access_token: content, expires_at: null, refresh_token: null };
      }
    }
  } catch (e) {
    console.error('Errore lettura token:', e);
  }
  return null;
}

// Salva i dati del token nel file
function saveTokenData(tokenData) {
  fs.writeFileSync(TOKEN_FILE, JSON.stringify(tokenData, null, 2));
  console.log('Token salvato in', TOKEN_FILE);
}

// Verifica se il token sta per scadere
function isTokenExpiringSoon(tokenData) {
  if (!tokenData || !tokenData.expires_at) {
    return false; // Token senza scadenza (vecchio formato o env var)
  }
  const now = Date.now();
  return now >= (tokenData.expires_at - REFRESH_MARGIN_MS);
}

// Verifica se il token è già scaduto
function isTokenExpired(tokenData) {
  if (!tokenData || !tokenData.expires_at) {
    return false; // Token senza scadenza
  }
  return Date.now() >= tokenData.expires_at;
}

// Refresha il token usando il refresh_token
async function refreshToken(tokenData) {
  if (!tokenData || !tokenData.refresh_token) {
    console.log('[Token Refresh] Nessun refresh_token disponibile');
    return null;
  }

  const now = new Date().toISOString();
  console.log(`[Token Refresh] ${now} - Tentativo di refresh del token...`);

  try {
    const response = await fetch(`https://${SHOPIFY_STORE}/admin/oauth/access_token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: SHOPIFY_API_KEY,
        client_secret: SHOPIFY_API_SECRET,
        grant_type: 'refresh_token',
        refresh_token: tokenData.refresh_token,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      console.error(`[Token Refresh] Errore HTTP ${response.status}:`, JSON.stringify(data));
      return null;
    }

    if (data.access_token) {
      const newTokenData = {
        access_token: data.access_token,
        refresh_token: data.refresh_token,
        expires_at: Date.now() + (data.expires_in * 1000),
        scope: data.scope,
        last_refresh: now,
      };
      saveTokenData(newTokenData);
      const expiresInMinutes = Math.round(data.expires_in / 60);
      console.log(`[Token Refresh] Token refreshato con successo. Scade tra ${expiresInMinutes} minuti.`);
      return newTokenData;
    } else {
      console.error('[Token Refresh] Risposta senza access_token:', JSON.stringify(data));
      return null;
    }
  } catch (error) {
    console.error('[Token Refresh] Errore durante il refresh:', error.message);
    return null;
  }
}

// Ottiene un token valido (con refresh automatico se necessario)
async function getValidToken() {
  // In produzione usa la variabile d'ambiente (senza scadenza)
  if (SHOPIFY_ACCESS_TOKEN) {
    return SHOPIFY_ACCESS_TOKEN;
  }

  // In sviluppo usa il file con supporto refresh
  let tokenData = getStoredTokenData();

  if (!tokenData) {
    console.log('[getValidToken] Nessun token salvato');
    return null;
  }

  // Verifica se il token sta per scadere o è già scaduto
  const expired = isTokenExpired(tokenData);
  const expiringSoon = isTokenExpiringSoon(tokenData);

  if ((expired || expiringSoon) && tokenData.refresh_token) {
    console.log(`[getValidToken] Token ${expired ? 'scaduto' : 'in scadenza'}, tentativo di refresh...`);
    const refreshedData = await refreshToken(tokenData);

    if (refreshedData) {
      return refreshedData.access_token;
    } else {
      // Refresh fallito
      if (expired) {
        // Token scaduto E refresh fallito = serve nuova autenticazione
        console.error('[getValidToken] Token scaduto e refresh fallito. Necessaria nuova autenticazione.');
        return null;
      }
      // Token in scadenza ma ancora valido, usa quello esistente
      console.log('[getValidToken] Refresh fallito, uso token esistente (ancora valido)');
      return tokenData.access_token;
    }
  }

  // Token senza scadenza o ancora valido
  return tokenData.access_token;
}

// Versione sincrona per retrocompatibilità (health check)
function getStoredToken() {
  if (SHOPIFY_ACCESS_TOKEN) {
    return SHOPIFY_ACCESS_TOKEN;
  }
  const tokenData = getStoredTokenData();
  return tokenData ? tokenData.access_token : null;
}

// Esegue una query GraphQL a Shopify con retry automatico su 401
async function shopifyGraphQL(query, variables = {}, retryCount = 0) {
  const MAX_RETRIES = 1;

  let token = await getValidToken();
  if (!token) {
    throw new Error('NO_TOKEN');
  }

  const response = await fetch(`https://${SHOPIFY_STORE}/admin/api/2026-01/graphql.json`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Shopify-Access-Token': token,
    },
    body: JSON.stringify({ query, variables }),
  });

  // Se riceviamo 401, proviamo a refreshare il token e riprovare
  if (response.status === 401 && retryCount < MAX_RETRIES) {
    console.log('[shopifyGraphQL] Ricevuto 401, tentativo di refresh token...');

    const tokenData = getStoredTokenData();
    if (tokenData && tokenData.refresh_token) {
      const refreshedData = await refreshToken(tokenData);
      if (refreshedData) {
        console.log('[shopifyGraphQL] Token refreshato, riprovo la chiamata...');
        return shopifyGraphQL(query, variables, retryCount + 1);
      }
    }

    // Refresh fallito o non disponibile
    console.error('[shopifyGraphQL] Impossibile refreshare il token dopo 401');
    throw new Error('TOKEN_EXPIRED');
  }

  if (!response.ok) {
    const errorText = await response.text();
    console.error(`[shopifyGraphQL] Errore HTTP ${response.status}:`, errorText);
    throw new Error(`Shopify API error: ${response.status}`);
  }

  const data = await response.json();

  // Controlla se ci sono errori GraphQL relativi all'autenticazione
  if (data.errors) {
    const authError = data.errors.find(e =>
      e.message?.toLowerCase().includes('access denied') ||
      e.message?.toLowerCase().includes('unauthorized') ||
      e.extensions?.code === 'ACCESS_DENIED'
    );

    if (authError && retryCount < MAX_RETRIES) {
      console.log('[shopifyGraphQL] Errore di autenticazione GraphQL, tentativo di refresh...');

      const tokenData = getStoredTokenData();
      if (tokenData && tokenData.refresh_token) {
        const refreshedData = await refreshToken(tokenData);
        if (refreshedData) {
          console.log('[shopifyGraphQL] Token refreshato, riprovo la chiamata...');
          return shopifyGraphQL(query, variables, retryCount + 1);
        }
      }

      throw new Error('TOKEN_EXPIRED');
    }
  }

  return data;
}

// Verifica HMAC per sicurezza OAuth
function verifyHmac(query) {
  const { hmac, ...rest } = query;
  const message = Object.keys(rest)
    .sort()
    .map(key => `${key}=${rest[key]}`)
    .join('&');
  const hash = crypto
    .createHmac('sha256', SHOPIFY_API_SECRET)
    .update(message)
    .digest('hex');
  return hash === hmac;
}

// ============================================
// OAUTH ENDPOINTS
// ============================================

// Step 1: Inizia il flusso OAuth
app.get('/auth', (req, res) => {
  const scopes = 'read_products,read_metaobjects,read_customers,read_orders,read_inventory,read_locations';
  const baseUrl = APP_URL || `http://localhost:${PORT}`;
  const redirectUri = `${baseUrl}/auth/callback`;
  const nonce = crypto.randomBytes(16).toString('hex');

  const authUrl = `https://${SHOPIFY_STORE}/admin/oauth/authorize?` +
    `client_id=${SHOPIFY_API_KEY}` +
    `&scope=${scopes}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${nonce}`;

  console.log('Redirect a:', authUrl);
  res.redirect(authUrl);
});

// Step 2: Callback OAuth - riceve il codice e lo scambia per il token
app.get('/auth/callback', async (req, res) => {
  const { code, shop, hmac, state } = req.query;

  if (!code || !shop) {
    return res.status(400).send('Parametri mancanti');
  }

  // Verifica HMAC
  if (!verifyHmac(req.query)) {
    return res.status(401).send('HMAC non valido');
  }

  try {
    // Scambia il codice per l'access token (con expiring=1 per ottenere refresh_token)
    const response = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: SHOPIFY_API_KEY,
        client_secret: SHOPIFY_API_SECRET,
        code: code,
        expiring: '1', // Richiede token con scadenza + refresh_token
      }),
    });

    const data = await response.json();

    if (data.access_token) {
      // Salva tutti i dati del token (incluso refresh_token e scadenza)
      const tokenData = {
        access_token: data.access_token,
        refresh_token: data.refresh_token || null,
        expires_at: data.expires_in ? Date.now() + (data.expires_in * 1000) : null,
        scope: data.scope,
      };
      saveTokenData(tokenData);

      const expiresInfo = data.expires_in
        ? `<p>Scadenza: ${Math.round(data.expires_in / 60)} minuti (refresh automatico attivo)</p>`
        : '<p>Token senza scadenza</p>';

      res.send(`
        <h1>Autorizzazione completata!</h1>
        <p>Access token ottenuto e salvato.</p>
        <p>Scopes: ${data.scope}</p>
        ${expiresInfo}
        <p>Puoi chiudere questa finestra.</p>
      `);
    } else {
      res.status(400).json({ error: 'Token non ricevuto', data });
    }
  } catch (error) {
    console.error('Errore OAuth:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// CACHE FULFILLMENT LOCATIONS
// ============================================

// Cache per le location di fulfillment (TTL 5 minuti)
let fulfillmentLocationsCache = null;
let fulfillmentLocationsCacheTime = 0;
const LOCATIONS_CACHE_TTL = 5 * 60 * 1000;

// Mappatura manuale country → location IDs (configurabile via env)
// Formato: COUNTRY_LOCATIONS=IT:gid://shopify/Location/123,FR:gid://shopify/Location/456
function getCountryLocationMap() {
  const envMap = process.env.COUNTRY_LOCATIONS;
  if (!envMap) return {};

  const map = {};
  envMap.split(',').forEach(pair => {
    const [country, locationId] = pair.split(':');
    if (country && locationId) {
      map[country.trim().toUpperCase()] = locationId.trim();
    }
  });
  return map;
}

// Ottiene le location che fulfillano ordini online (con info country)
async function getFulfillmentLocations() {
  const now = Date.now();
  if (fulfillmentLocationsCache && (now - fulfillmentLocationsCacheTime) < LOCATIONS_CACHE_TTL) {
    return fulfillmentLocationsCache;
  }

  const query = `
    query GetLocations {
      locations(first: 20, includeLegacy: true, includeInactive: false) {
        edges {
          node {
            id
            name
            fulfillsOnlineOrders
            address {
              countryCode
            }
          }
        }
      }
    }
  `;

  try {
    const data = await shopifyGraphQL(query);

    if (data.errors) {
      console.error('Errore query locations:', data.errors);
      return { all: [], byCountry: {} };
    }

    const locations = data.data?.locations?.edges?.map(e => e.node) || [];

    // Filtra solo le location che fulfillano ordini online
    const fulfillmentLocations = locations.filter(l => l.fulfillsOnlineOrders);

    // Raggruppa per country code
    const byCountry = {};
    for (const loc of fulfillmentLocations) {
      const countryCode = loc.address?.countryCode;
      if (countryCode) {
        if (!byCountry[countryCode]) {
          byCountry[countryCode] = [];
        }
        byCountry[countryCode].push(loc.id);
      }
    }

    fulfillmentLocationsCache = {
      all: fulfillmentLocations.map(l => l.id),
      byCountry
    };

    fulfillmentLocationsCacheTime = now;
    console.log(`Cached ${fulfillmentLocationsCache.all.length} fulfillment locations:`, byCountry);

    return fulfillmentLocationsCache;
  } catch (error) {
    console.error('Errore getFulfillmentLocations:', error.message);
    // Propaga l'errore per gestione token
    if (error.message === 'NO_TOKEN' || error.message === 'TOKEN_EXPIRED') {
      throw error;
    }
    return { all: [], byCountry: {} };
  }
}

// ============================================
// API ENDPOINTS
// ============================================

// Health check
app.get('/', (req, res) => {
  const hasToken = !!getStoredToken();
  res.json({
    status: 'ok',
    hasToken,
    message: hasToken ? 'Token presente, API pronta' : 'Token mancante, vai su /auth per autorizzare'
  });
});

// Stato del token (per debug)
app.get('/token-status', (req, res) => {
  const tokenData = getStoredTokenData();

  if (!tokenData) {
    return res.json({
      status: 'missing',
      message: 'Nessun token salvato. Vai su /auth per autorizzare.'
    });
  }

  const now = Date.now();
  const hasExpiry = !!tokenData.expires_at;
  const hasRefreshToken = !!tokenData.refresh_token;

  let expiresIn = null;
  let expired = false;
  let expiringSoon = false;

  if (hasExpiry) {
    expiresIn = Math.round((tokenData.expires_at - now) / 1000 / 60); // minuti
    expired = isTokenExpired(tokenData);
    expiringSoon = isTokenExpiringSoon(tokenData);
  }

  res.json({
    status: expired ? 'expired' : 'valid',
    hasRefreshToken,
    expiresIn: hasExpiry ? `${expiresIn} minuti` : 'mai (token permanente)',
    expiresAt: hasExpiry ? new Date(tokenData.expires_at).toISOString() : null,
    isExpiringSoon: expiringSoon,
    willAutoRefresh: hasRefreshToken && (expired || expiringSoon),
    lastRefresh: tokenData.last_refresh || null,
    scope: tokenData.scope || 'unknown',
    message: expired
      ? (hasRefreshToken ? 'Token scaduto, verrà refreshato alla prossima richiesta API' : 'Token scaduto, vai su /auth')
      : 'Token valido'
  });
});

// Forza il refresh del token (per test/debug)
app.post('/token-refresh', async (req, res) => {
  const tokenData = getStoredTokenData();

  if (!tokenData) {
    return res.status(404).json({
      success: false,
      error: 'Nessun token salvato. Vai su /auth per autorizzare.'
    });
  }

  if (!tokenData.refresh_token) {
    return res.status(400).json({
      success: false,
      error: 'Token senza refresh_token. Riesegui autenticazione su /auth.'
    });
  }

  const refreshedData = await refreshToken(tokenData);

  if (refreshedData) {
    const expiresInMinutes = Math.round((refreshedData.expires_at - Date.now()) / 1000 / 60);
    res.json({
      success: true,
      message: 'Token refreshato con successo',
      expiresIn: `${expiresInMinutes} minuti`,
      expiresAt: new Date(refreshedData.expires_at).toISOString()
    });
  } else {
    res.status(500).json({
      success: false,
      error: 'Refresh fallito. Controlla i log del server. Potrebbe essere necessario riautenticarsi su /auth.'
    });
  }
});

// Debug: mostra tutte le location
app.get('/api/debug/locations', async (req, res) => {
  const query = `
    query GetLocations {
      locations(first: 50, includeLegacy: true, includeInactive: false) {
        edges {
          node {
            id
            name
            fulfillsOnlineOrders
            address {
              country
              countryCode
            }
          }
        }
      }
    }
  `;

  try {
    const data = await shopifyGraphQL(query);
    const locations = data.data?.locations?.edges?.map(e => e.node) || [];

    res.json({
      count: locations.length,
      locations: locations.map(l => ({
        id: l.id,
        name: l.name,
        fulfillsOnlineOrders: l.fulfillsOnlineOrders,
        country: l.address?.country,
        countryCode: l.address?.countryCode
      }))
    });
  } catch (error) {
    console.error('Errore debug locations:', error.message);
    if (error.message === 'NO_TOKEN' || error.message === 'TOKEN_EXPIRED') {
      return res.status(401).json({
        error: 'Token mancante o scaduto',
        message: 'Il refresh automatico ha fallito. Vai su /auth per riautenticarti.'
      });
    }
    res.status(500).json({ error: error.message });
  }
});

// Ottieni prodotti per promo ID
app.get('/api/composer/products', async (req, res) => {
  const { promo_id, country } = req.query;

  if (!promo_id) {
    return res.status(400).json({ error: 'promo_id richiesto' });
  }

  try {
    // Ottieni le location di fulfillment (gestisce automaticamente il token)
    const fulfillmentLocations = await getFulfillmentLocations();

    // Determina quali location usare per il calcolo availability
    let targetLocationIds = fulfillmentLocations.all;

    // Se è specificato un country, filtra per le location di quel paese
    if (country) {
      const countryUpper = country.toUpperCase();

      // Prima controlla la mappatura manuale (env var)
      const manualMap = getCountryLocationMap();
      if (manualMap[countryUpper]) {
        targetLocationIds = [manualMap[countryUpper]];
        console.log(`Using manual location mapping for ${countryUpper}:`, targetLocationIds);
      }
      // Altrimenti usa le location del paese
      else if (fulfillmentLocations.byCountry[countryUpper]) {
        targetLocationIds = fulfillmentLocations.byCountry[countryUpper];
        console.log(`Using country-based locations for ${countryUpper}:`, targetLocationIds);
      } else {
        console.log(`No specific locations for ${countryUpper}, using all:`, targetLocationIds);
      }
    }

    // Query GraphQL con inventoryLevels per availability reale per location
    const query = `
      query GetPromoProducts($handle: String!) {
        metaobjectByHandle(handle: {type: "promozione", handle: $handle}) {
          id
          handle
          fields {
            key
            value
          }
          referencedBy(first: 50) {
            edges {
              node {
                referencer {
                  ... on Product {
                    id
                    title
                    handle
                    featuredImage {
                      url
                    }
                    modello: metafield(namespace: "custom", key: "modello") {
                      value
                    }
                    colore: metafield(namespace: "custom", key: "colore") {
                      value
                    }
                    priceRange {
                      minVariantPrice {
                        amount
                        currencyCode
                      }
                    }
                    variants(first: 20) {
                      edges {
                        node {
                          id
                          title
                          availableForSale
                          price
                          inventoryPolicy
                          inventoryItem {
                            tracked
                            inventoryLevels(first: 10) {
                              edges {
                                node {
                                  quantities(names: ["available"]) {
                                    name
                                    quantity
                                  }
                                  location {
                                    id
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    `;

    const data = await shopifyGraphQL(query, { handle: promo_id });

    if (data.errors) {
      return res.status(400).json({ errors: data.errors });
    }

    const metaobject = data.data?.metaobjectByHandle;

    if (!metaobject) {
      return res.json({
        promo_id,
        count: 0,
        products: [],
        message: 'Promo non trovata'
      });
    }

    // Estrai i prodotti dalle references
    const products = metaobject.referencedBy?.edges
      ?.map(edge => edge.node?.referencer)
      ?.filter(p => p && p.id) || [];

    // Estrai info promo
    const promoName = metaobject.fields?.find(f => f.key === 'name')?.value;

    res.json({
      promo_id,
      promo_name: promoName,
      country: country || null,
      count: products.length,
      products: products.map(p => ({
        id: p.id,
        title: p.title,
        handle: p.handle,
        modello: p.modello?.value || null,
        colore: p.colore?.value || null,
        image: p.featuredImage?.url,
        price: p.priceRange?.minVariantPrice,
        variants: p.variants?.edges?.map(v => {
          const variant = v.node;
          const tracked = variant.inventoryItem?.tracked ?? true;
          const inventoryPolicy = variant.inventoryPolicy || 'DENY';
          const inventoryLevels = variant.inventoryItem?.inventoryLevels?.edges || [];

          // Calcola l'inventario disponibile dalle location target (filtrate per country se specificato)
          let totalAvailable = 0;
          for (const level of inventoryLevels) {
            const locationId = level.node?.location?.id;
            // Filtra solo le location target
            if (targetLocationIds.length === 0 || targetLocationIds.includes(locationId)) {
              const availableQty = level.node?.quantities?.find(q => q.name === 'available')?.quantity || 0;
              totalAvailable += availableQty;
            }
          }

          // Calcolo availability:
          // - Se non tracciato → disponibile
          // - Se policy CONTINUE → disponibile (overselling consentito)
          // - Se policy DENY → disponibile solo se qty > 0
          let available;
          if (!tracked) {
            available = true;
          } else if (inventoryPolicy === 'CONTINUE') {
            available = true;
          } else {
            available = totalAvailable > 0;
          }

          return {
            id: variant.id,
            title: variant.title,
            available,
            price: variant.price
          };
        })
      }))
    });

  } catch (error) {
    console.error('Errore API:', error.message);
    if (error.message === 'NO_TOKEN' || error.message === 'TOKEN_EXPIRED') {
      return res.status(401).json({
        error: 'Token mancante o scaduto',
        message: 'Il refresh automatico ha fallito. Vai su /auth per riautenticarti.'
      });
    }
    res.status(500).json({ error: error.message });
  }
});

// Ottieni dettagli metaobject promo
app.get('/api/composer/promo/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const query = `
      query GetPromo($id: ID!) {
        metaobject(id: $id) {
          id
          handle
          type
          fields {
            key
            value
          }
        }
      }
    `;

    const data = await shopifyGraphQL(query, { id });
    res.json(data.data?.metaobject || { error: 'Promo non trovata' });

  } catch (error) {
    console.error('Errore API promo:', error.message);
    if (error.message === 'NO_TOKEN' || error.message === 'TOKEN_EXPIRED') {
      return res.status(401).json({
        error: 'Token mancante o scaduto',
        message: 'Il refresh automatico ha fallito. Vai su /auth per riautenticarti.'
      });
    }
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// START SERVER
// ============================================

app.listen(PORT, () => {
  console.log(`\n🚀 Composer API running on http://localhost:${PORT}`);
  console.log(`\n📋 Endpoints:`);
  console.log(`   GET  /              - Health check`);
  console.log(`   GET  /token-status  - Stato del token (scadenza, refresh)`);
  console.log(`   POST /token-refresh - Forza refresh manuale del token`);
  console.log(`   GET  /auth          - Inizia OAuth flow`);
  console.log(`   GET  /api/composer/products?promo_id=XXX&country=IT - Prodotti per promo`);
  console.log(`   GET  /api/composer/promo/:id - Dettagli promo`);
  console.log(`   GET  /api/debug/locations - Debug location di fulfillment\n`);

  const tokenData = getStoredTokenData();
  if (tokenData) {
    console.log('✅ Token presente, API pronta!');
    if (tokenData.refresh_token) {
      console.log('🔄 Refresh automatico attivo\n');
    } else {
      console.log('⚠️  Nessun refresh_token - token permanente o vecchio formato\n');
    }
  } else {
    console.log('⚠️  Token mancante! Vai su http://localhost:' + PORT + '/auth per autorizzare\n');
  }
});
