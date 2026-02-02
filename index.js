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

// Refresha il token usando il refresh_token
async function refreshToken(tokenData) {
  if (!tokenData || !tokenData.refresh_token) {
    console.log('Nessun refresh_token disponibile');
    return null;
  }

  console.log('Refreshing token...');

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

    if (data.access_token) {
      const newTokenData = {
        access_token: data.access_token,
        refresh_token: data.refresh_token,
        expires_at: Date.now() + (data.expires_in * 1000),
        scope: data.scope,
      };
      saveTokenData(newTokenData);
      console.log('Token refreshato con successo');
      return newTokenData;
    } else {
      console.error('Errore refresh token:', data);
      return null;
    }
  } catch (error) {
    console.error('Errore durante il refresh del token:', error);
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
    return null;
  }

  // Verifica se il token sta per scadere e ha un refresh_token
  if (isTokenExpiringSoon(tokenData) && tokenData.refresh_token) {
    const refreshedData = await refreshToken(tokenData);
    if (refreshedData) {
      tokenData = refreshedData;
    } else {
      // Refresh fallito, il token potrebbe essere ancora valido
      console.log('Refresh fallito, uso token esistente');
    }
  }

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

// Ottiene le location che fulfillano ordini online
async function getFulfillmentLocations(token) {
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
          }
        }
      }
    }
  `;

  try {
    const response = await fetch(`https://${SHOPIFY_STORE}/admin/api/2026-01/graphql.json`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': token,
      },
      body: JSON.stringify({ query }),
    });

    const data = await response.json();

    if (data.errors) {
      console.error('Errore query locations:', data.errors);
      return [];
    }

    const locations = data.data?.locations?.edges?.map(e => e.node) || [];

    // Filtra solo le location che fulfillano ordini online
    fulfillmentLocationsCache = locations
      .filter(l => l.fulfillsOnlineOrders)
      .map(l => l.id);

    fulfillmentLocationsCacheTime = now;
    console.log(`Cached ${fulfillmentLocationsCache.length} fulfillment locations`);

    return fulfillmentLocationsCache;
  } catch (error) {
    console.error('Errore getFulfillmentLocations:', error);
    return [];
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
  let isExpired = false;
  let isExpiringSoon = false;

  if (hasExpiry) {
    expiresIn = Math.round((tokenData.expires_at - now) / 1000 / 60); // minuti
    isExpired = tokenData.expires_at < now;
    isExpiringSoon = isTokenExpiringSoon(tokenData);
  }

  res.json({
    status: isExpired ? 'expired' : 'valid',
    hasRefreshToken,
    expiresIn: hasExpiry ? `${expiresIn} minuti` : 'mai (token permanente)',
    isExpiringSoon,
    willAutoRefresh: hasRefreshToken && isExpiringSoon,
    scope: tokenData.scope || 'unknown',
    message: isExpired
      ? (hasRefreshToken ? 'Token scaduto, verra refreshato automaticamente' : 'Token scaduto, vai su /auth')
      : 'Token valido'
  });
});

// Ottieni prodotti per promo ID
app.get('/api/composer/products', async (req, res) => {
  const { promo_id, country } = req.query;

  if (!promo_id) {
    return res.status(400).json({ error: 'promo_id richiesto' });
  }

  const token = await getValidToken();
  if (!token) {
    return res.status(401).json({
      error: 'Token mancante o scaduto',
      message: 'Vai su /auth per autorizzare l\'app'
    });
  }

  try {
    // Ottieni le location di fulfillment
    const fulfillmentLocationIds = await getFulfillmentLocations(token);

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

    const response = await fetch(`https://${SHOPIFY_STORE}/admin/api/2026-01/graphql.json`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': token,
      },
      body: JSON.stringify({
        query,
        variables: {
          handle: promo_id
        }
      }),
    });

    const data = await response.json();

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
        image: p.featuredImage?.url,
        price: p.priceRange?.minVariantPrice,
        variants: p.variants?.edges?.map(v => {
          const variant = v.node;
          const tracked = variant.inventoryItem?.tracked ?? true;
          const inventoryPolicy = variant.inventoryPolicy || 'DENY';
          const inventoryLevels = variant.inventoryItem?.inventoryLevels?.edges || [];

          // Calcola l'inventario disponibile dalle location di fulfillment
          let totalAvailable = 0;
          for (const level of inventoryLevels) {
            const locationId = level.node?.location?.id;
            // Filtra solo le location di fulfillment (se disponibili)
            if (fulfillmentLocationIds.length === 0 || fulfillmentLocationIds.includes(locationId)) {
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
    console.error('Errore API:', error);
    res.status(500).json({ error: error.message });
  }
});

// Ottieni dettagli metaobject promo
app.get('/api/composer/promo/:id', async (req, res) => {
  const { id } = req.params;

  const token = await getValidToken();
  if (!token) {
    return res.status(401).json({ error: 'Token mancante o scaduto', message: 'Vai su /auth per autorizzare l\'app' });
  }

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

    const response = await fetch(`https://${SHOPIFY_STORE}/admin/api/2026-01/graphql.json`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': token,
      },
      body: JSON.stringify({
        query,
        variables: { id }
      }),
    });

    const data = await response.json();
    res.json(data.data?.metaobject || { error: 'Promo non trovata' });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// START SERVER
// ============================================

app.listen(PORT, () => {
  console.log(`\n🚀 Composer API running on http://localhost:${PORT}`);
  console.log(`\n📋 Endpoints:`);
  console.log(`   GET /              - Health check`);
  console.log(`   GET /token-status  - Stato del token (scadenza, refresh)`);
  console.log(`   GET /auth          - Inizia OAuth flow`);
  console.log(`   GET /api/composer/products?promo_id=XXX - Prodotti per promo`);
  console.log(`   GET /api/composer/promo/:id - Dettagli promo\n`);

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
