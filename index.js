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

// Legge il token (priorità: env var > file)
function getStoredToken() {
  // In produzione usa la variabile d'ambiente
  if (SHOPIFY_ACCESS_TOKEN) {
    return SHOPIFY_ACCESS_TOKEN;
  }
  // In sviluppo usa il file
  try {
    if (fs.existsSync(TOKEN_FILE)) {
      return fs.readFileSync(TOKEN_FILE, 'utf8').trim();
    }
  } catch (e) {
    console.error('Errore lettura token:', e);
  }
  return null;
}

// Salva il token nel file
function saveToken(token) {
  fs.writeFileSync(TOKEN_FILE, token);
  console.log('Token salvato in', TOKEN_FILE);
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
  const scopes = 'read_products,read_metaobjects,read_customers,read_orders';
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
    // Scambia il codice per l'access token
    const response = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        client_id: SHOPIFY_API_KEY,
        client_secret: SHOPIFY_API_SECRET,
        code: code,
      }),
    });

    const data = await response.json();

    if (data.access_token) {
      saveToken(data.access_token);
      res.send(`
        <h1>Autorizzazione completata!</h1>
        <p>Access token ottenuto e salvato.</p>
        <p>Scopes: ${data.scope}</p>
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

// Ottieni prodotti per promo ID
app.get('/api/composer/products', async (req, res) => {
  const { promo_id } = req.query;

  if (!promo_id) {
    return res.status(400).json({ error: 'promo_id richiesto' });
  }

  const token = getStoredToken();
  if (!token) {
    return res.status(401).json({
      error: 'Token mancante',
      message: 'Vai su /auth per autorizzare l\'app'
    });
  }

  try {
    // Query GraphQL usando referencedBy per trovare i prodotti che referenziano la promo
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
      count: products.length,
      products: products.map(p => ({
        id: p.id,
        title: p.title,
        handle: p.handle,
        image: p.featuredImage?.url,
        price: p.priceRange?.minVariantPrice,
        variants: p.variants?.edges?.map(v => ({
          id: v.node.id,
          title: v.node.title,
          available: v.node.availableForSale,
          price: v.node.price
        }))
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

  const token = getStoredToken();
  if (!token) {
    return res.status(401).json({ error: 'Token mancante' });
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
  console.log(`   GET /           - Health check`);
  console.log(`   GET /auth       - Inizia OAuth flow`);
  console.log(`   GET /api/composer/products?promo_id=XXX - Prodotti per promo`);
  console.log(`   GET /api/composer/promo/:id - Dettagli promo\n`);

  if (getStoredToken()) {
    console.log('✅ Token presente, API pronta!\n');
  } else {
    console.log('⚠️  Token mancante! Vai su http://localhost:' + PORT + '/auth per autorizzare\n');
  }
});
