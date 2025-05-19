const express = require('express');
const cors = require('cors');
const compression = require('compression');
const { createClient } = require('@supabase/supabase-js');
const NodeCache = require('node-cache');
const { body, query, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const axios = require('axios');
require('dotenv').config();

const app = express();
const cache = new NodeCache({ stdTTL: 600, checkperiod: 120 });
const PORT = process.env.PORT || 3001;

// Middleware
const corsOptions = {
  origin: true, // Autorise toutes les origines pour tester (à ajuster plus tard)
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(compression());
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'public, max-age=600');
  next();
});

// Middleware d'authentification
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1] || req.cookies?.token;
  if (!token) {
    req.user = null; // Pas d'authentification, mais passe au suivant
    return next();
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const { data: user, error } = await supabase.auth.getUser(decoded.token);
    if (error || !user) return res.status(401).json({ error: 'Token invalide' });

    req.user = user.user;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Token invalide' });
  }
};

// Gestion globale des erreurs
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Une erreur interne est survenue' });
});

// Initialiser Supabase
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// Configuration de multer pour les uploads
const storage = multer.memoryStorage();
const upload = multer({ storage });

// Route de santé
app.get('/api/health', (req, res) => {
  res.status(200).json({ message: 'Serveur opérationnel', timestamp: new Date().toISOString() });
});

// Auth endpoints
app.get('/api/auth/check', authenticate, (req, res) => {
  if (req.user) {
    res.json({ user: { id: req.user.id, email: req.user.email, role: req.user.role || 'user' } });
  } else {
    res.json({ user: null }); // Retourne null si non authentifié
  }
});

app.post('/api/auth/register', [
  body('email').isEmail().withMessage('Email invalide'),
  body('password').notEmpty().withMessage('Mot de passe requis'),
  body('first_name').notEmpty().withMessage('Prénom requis'),
  body('last_name').notEmpty().withMessage('Nom requis'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

  const { email, password, first_name, last_name, phone_number } = req.body;
  try {
    const { data, error } = await supabase.auth.signUp({ email, password });
    if (error) throw error;

    const { error: insertError } = await supabase.from('users').insert({
      auth_id: data.user.id,
      email,
      first_name,
      last_name,
      phone_number,
    });
    if (insertError) throw insertError;

    const token = jwt.sign({ token: data.session.access_token }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/auth/login', [
  body('email').isEmail().withMessage('Email invalide'),
  body('password').notEmpty().withMessage('Mot de passe requis'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

  const { email, password } = req.body;
  try {
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) throw error;

    const { data: vendorData, error: vendorError } = await supabase
      .from('vendors')
      .select('role')
      .eq('auth_id', data.user.id)
      .single();
    if (vendorError && vendorError.code !== 'PGRST116') throw vendorError;
    const role = vendorData?.role || 'user';

    const token = jwt.sign({ token: data.session.access_token }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
});

app.post('/api/auth/logout', authenticate, async (req, res) => {
  try {
    const { error } = await supabase.auth.signOut();
    if (error) throw error;
    res.json({ message: 'Déconnexion réussie' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/forgot-password', [
  body('email').isEmail().withMessage('Email invalide'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

  const { email } = req.body;
  try {
    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: `${process.env.FRONTEND_URL}/reset-password`,
    });
    if (error) throw error;
    res.json({ message: 'Lien de réinitialisation envoyé' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// User endpoints
app.get('/api/users/me', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('users')
      .select('first_name, last_name, phone_number, email')
      .eq('auth_id', req.user.id)
      .single();
    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/users', authenticate, async (req, res) => {
  try {
    const { email, first_name, last_name, phone_number } = req.body;
    const { error } = await supabase.from('users').insert({
      auth_id: req.user.id,
      email,
      first_name,
      last_name,
      phone_number,
    });
    if (error) throw error;
    res.status(201).json({ message: 'User created' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Profile endpoints
app.get('/api/profiles/me', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('profiles')
      .select('role, country')
      .eq('auth_id', req.user.id)
      .single();
    if (error && error.code !== 'PGRST116') throw error;
    res.json(data || {});
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/profiles', authenticate, async (req, res) => {
  const { role, country, email } = req.body;
  try {
    const { data, error } = await supabase
      .from('profiles')
      .insert({ auth_id: req.user.id, role, country, email })
      .select()
      .single();
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/profiles/me', authenticate, async (req, res) => {
  const { country } = req.body;
  try {
    const { data, error } = await supabase
      .from('profiles')
      .upsert({ auth_id: req.user.id, country }, { onConflict: 'auth_id' })
      .select()
      .single();
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Vendor endpoints
app.get('/api/vendors', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('vendors')
      .select('auth_id, shop_name, phone_number, country');
    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/vendors/active', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('vendors')
      .select('auth_id')
      .eq('is_store_active', true);
    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/vendors/me', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('vendors')
      .select('id, is_store_active, current_plan, subscription_end_date, quota_limit')
      .eq('auth_id', req.user.id)
      .maybeSingle();
    if (error) throw error;
    res.json(data || null);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/vendors/:vendor_id', authenticate, async (req, res) => {
  const { vendor_id } = req.params;
  const { activeOnly } = req.query;
  try {
    let query = supabase
      .from('vendors')
      .select('auth_id, shop_name, vendor_name, phone_number, country, is_store_active')
      .eq('auth_id', vendor_id);
    
    if (activeOnly === 'true') {
      query = query.eq('is_store_active', true);
    }

    const { data, error } = await query.single();
    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/vendors', authenticate, async (req, res) => {
  try {
    const { vendor_name, shop_name, address, country, phone_number, email, vendor_code, current_plan, subscription_end_date, quota_limit, is_store_active } = req.body;
    const { data, error } = await supabase
      .from('vendors')
      .insert({
        auth_id: req.user.id,
        vendor_name,
        shop_name,
        address,
        country,
        phone_number,
        email,
        vendor_code,
        current_plan,
        subscription_end_date,
        quota_limit,
        is_store_active,
      })
      .select()
      .single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.put('/api/vendors/me', authenticate, async (req, res) => {
  try {
    const { pack, subscription_end_date, current_plan, quota_limit, is_store_active } = req.body;
    const updateData = {};
    if (pack) updateData.pack = pack;
    if (subscription_end_date) updateData.subscription_end_date = subscription_end_date;
    if (current_plan) updateData.current_plan = current_plan;
    if (quota_limit !== undefined) updateData.quota_limit = quota_limit;
    if (is_store_active !== undefined) updateData.is_store_active = is_store_active;

    const { data, error } = await supabase
      .from('vendors')
      .update(updateData)
      .eq('auth_id', req.user.id)
      .select()
      .single();
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/vendors/:vendorId/quota', authenticate, async (req, res) => {
  const { vendorId } = req.params;
  const cacheKey = `quota_${vendorId}`;

  const cached = cache.get(cacheKey);
  if (cached) return res.json(cached);

  try {
    const { data: vendorData, error: vendorError } = await supabase
      .from('vendors')
      .select('current_plan')
      .eq('auth_id', vendorId)
      .single();

    if (vendorError) throw vendorError;

    const { data: productsData, error: productsError, count } = await supabase
      .from('products')
      .select('id', { count: 'exact' })
      .eq('vendor_id', vendorId);

    if (productsError) throw productsError;

    const packLimits = {
      'Pack Gratuit': 2,
      'Pack Basique': 10,
      'Pack Pro': 25,
      'Pack VIP': Infinity,
    };

    const result = {
      currentCount: count || 0,
      limit: packLimits[vendorData.current_plan] || 0,
    };

    cache.set(cacheKey, result);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Product endpoints
app.get('/api/products', async (req, res) => {
  const { page = 1, limit = 10, category, country, priceMin, priceMax, condition, search, vendorIds, isActive, stockStatus, vendorId } = req.query;
  const start = (page - 1) * limit;
  const end = start + parseInt(limit) - 1;

  const cacheKey = `products_${page}_${limit}_${category || ''}_${country || ''}_${priceMin || '0'}_${priceMax || 'Infinity'}_${condition || ''}_${search || ''}_${vendorIds || ''}_${isActive || ''}_${stockStatus || ''}_${vendorId || ''}`;
  const cached = cache.get(cacheKey);
  if (cached) return res.json(cached);

  let query = supabase.from('products').select('id, name, price, stock, stock_status, category, countries, photo_urls, vendor_id, condition', { count: 'exact' }).range(start, end);

  if (category && category !== 'all') query = query.eq('category', category);
  if (country && country !== 'all') query = query.contains('countries', [country]);
  if (priceMin || priceMax) query = query.filter('price', 'gte', parseFloat(priceMin) || 0).filter('price', 'lte', parseFloat(priceMax) || Infinity);
  if (condition && condition !== 'all') query = query.eq('condition', condition);
  if (search) query = query.ilike('name', `%${search}%`);
  if (vendorIds) {
    const vendorIdArray = vendorIds.split(',');
    query = query.in('vendor_id', vendorIdArray);
  }
  if (isActive) query = query.eq('is_active', isActive === 'true');
  if (stockStatus) query = query.eq('stock_status', stockStatus);
  if (vendorId) query = query.eq('vendor_id', vendorId);

  try {
    const { data, error, count } = await query;
    if (error) throw error;
    const result = { data, total: count };
    cache.set(cacheKey, result);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/products/suggestions', async (req, res) => {
  const { query, country } = req.query;
  if (!query) return res.status(400).json({ error: 'Requête de recherche requise' });

  const expandedQueries = query.split(',').map(q => q.trim());
  try {
    let supabaseQuery = supabase
      .from('products')
      .select('name, category')
      .or(expandedQueries.map(q => `name.ilike.%${q}%,category.ilike.%${q}%`).join(','))
      .eq('is_active', true)
      .eq('stock_status', 'disponible')
      .limit(5);

    if (country && country !== 'all') {
      supabaseQuery = supabaseQuery.contains('countries', [country]);
    }

    const { data, error } = await supabaseQuery;
    if (error) throw error;
    res.json(data || []);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/products/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase
      .from('products')
      .select('id, name, price, stock, stock_status, category, countries, photo_urls, vendor_id, condition, description')
      .eq('id', id)
      .single();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Produit non trouvé' });
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/products/mine', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('products')
      .select('*')
      .eq('vendor_id', req.user.id);
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/products/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { name, description, price, category, stock, photo_urls, countries, stock_status, condition } = req.body;
  try {
    const { data: existingProduct, error: fetchError } = await supabase
      .from('products')
      .select('vendor_id')
      .eq('id', id)
      .single();
    if (fetchError) throw fetchError;
    if (existingProduct.vendor_id !== req.user.id) return res.status(403).json({ error: 'Non autorisé' });

    const { error } = await supabase
      .from('products')
      .update({
        name,
        description,
        price,
        category,
        stock,
        photo_urls,
        countries,
        stock_status,
        condition,
        updated_at: new Date().toISOString(),
      })
      .eq('id', id);
    if (error) throw error;
    res.json({ message: 'Produit mis à jour avec succès' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Shop endpoints (remplacement de /shops par /vendors pour cohérence)
app.get('/api/shops', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('vendors')
      .select('auth_id, shop_name, phone_number, country');
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/shops/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase
      .from('vendors')
      .select('auth_id, shop_name, vendor_name, phone_number, country')
      .eq('auth_id', id)
      .single();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Boutique non trouvée' });
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/shops/:id/products', async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase
      .from('products')
      .select('id, name, price, stock, stock_status, category, countries, photo_urls, vendor_id, condition')
      .eq('vendor_id', id);
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Favorite endpoints
app.get('/api/favorites', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('favorites')
      .select('product:products(*)')
      .eq('user_id', req.user.id);
    if (error) throw error;
    res.json(data.map(item => item.product) || []);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/favorites/mine', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('favorites')
      .select('product_id')
      .eq('user_id', req.user.id);
    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/favorites/check', authenticate, [
  query('productId').notEmpty().withMessage('Product ID requis'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

  const { productId } = req.query;
  try {
    const { data, error } = await supabase
      .from('favorites')
      .select('id')
      .eq('user_id', req.user.id)
      .eq('product_id', productId)
      .maybeSingle();
    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/favorites/toggle', authenticate, [
  body('productId').notEmpty().withMessage('Product ID requis'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

  const { productId } = req.body;
  try {
    const { data: existing, error: fetchError } = await supabase
      .from('favorites')
      .select('*')
      .eq('user_id', req.user.id)
      .eq('product_id', productId);
    if (fetchError) throw fetchError;

    if (existing.length > 0) {
      const { error } = await supabase
        .from('favorites')
        .delete()
        .eq('user_id', req.user.id)
        .eq('product_id', productId);
      if (error) throw error;
      res.json({ message: 'Retiré des favoris', isFavorite: false });
    } else {
      const { error } = await supabase
        .from('favorites')
        .insert({ user_id: req.user.id, product_id: productId });
      if (error) throw error;
      res.json({ message: 'Ajouté aux favoris', isFavorite: true });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Cart endpoints
app.get('/api/cart', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('cart')
      .select('id, quantity, product:products(*, vendors(vendor_name, shop_name, phone_number))')
      .eq('user_id', req.user.id);
    if (error) throw error;
    res.json(data || []);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/cart/mine', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('cart')
      .select('product_id')
      .eq('user_id', req.user.id);
    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/cart/check', authenticate, [
  query('productId').notEmpty().withMessage('Product ID requis'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

  const { productId } = req.query;
  try {
    const { data, error } = await supabase
      .from('cart')
      .select('id')
      .eq('user_id', req.user.id)
      .eq('product_id', productId)
      .maybeSingle();
    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/cart/toggle', authenticate, [
  body('productId').notEmpty().withMessage('Product ID requis'),
  body('quantity').isInt({ min: 1 }).withMessage('Quantité invalide'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

  const { productId, quantity = 1 } = req.body;
  try {
    const { data: existing, error: fetchError } = await supabase
      .from('cart')
      .select('*')
      .eq('user_id', req.user.id)
      .eq('product_id', productId);
    if (fetchError) throw fetchError;

    if (existing.length > 0) {
      const { error } = await supabase
        .from('cart')
        .delete()
        .eq('user_id', req.user.id)
        .eq('product_id', productId);
      if (error) throw error;
      res.json({ message: 'Retiré du panier', isInCart: false });
    } else {
      const { error } = await supabase
        .from('cart')
        .insert({ user_id: req.user.id, product_id: productId, quantity });
      if (error) throw error;
      res.json({ message: 'Ajouté au panier', isInCart: true });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/cart/:id', authenticate, [
  body('quantity').isInt({ min: 1 }).withMessage('Quantité invalide'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

  const { id } = req.params;
  const { quantity } = req.body;
  try {
    const { data, error } = await supabase
      .from('cart')
      .update({ quantity })
      .eq('id', id)
      .eq('user_id', req.user.id)
      .select('id, quantity')
      .single();
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/cart/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    const { error } = await supabase
      .from('cart')
      .delete()
      .eq('id', id)
      .eq('user_id', req.user.id);
    if (error) throw error;
    res.json({ message: 'Produit retiré du panier' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Notification endpoints
app.get('/api/notifications', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('notifications')
      .select(`
        *,
        vendors!fk_notifications_sender (
          vendor_name,
          shop_name
        )
      `)
      .or(`receiver_id.eq.${req.user.id},target.eq.all`)
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/notifications/unread-count', authenticate, async (req, res) => {
  try {
    const { count, error } = await supabase
      .from('notifications')
      .select('id', { count: 'exact' })
      .or(`receiver_id.eq.${req.user.id},target.eq.all`)
      .eq('is_read', false);
    if (error) throw error;
    res.json({ count });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.put('/api/notifications/:id/read', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    const { error } = await supabase
      .from('notifications')
      .update({ is_read: true })
      .eq('id', id);
    if (error) throw error;
    res.json({ message: 'Notification marked as read' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/notifications', authenticate, [
  body('receiverId').notEmpty().withMessage('Receiver ID requis'),
  body('message').notEmpty().withMessage('Message requis'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { receiverId, message, target = 'all' } = req.body;
  try {
    const { error } = await supabase.from('notifications').insert({
      sender_id: req.user.id,
      receiver_id: receiverId,
      message,
      target,
      created_at: new Date().toISOString(),
    });
    if (error) throw error;
    res.status(200).json({ message: 'Notification envoyée' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Subscription endpoints
app.get('/api/subscription', authenticate, async (req, res) => {
  try {
    const { data: vendorData, error } = await supabase
      .from('vendors')
      .select('current_plan')
      .eq('auth_id', req.user.id)
      .single();
    if (error) throw error;

    const packLimits = {
      'Pack Gratuit': 2,
      'Pack Basique': 10,
      'Pack Pro': 25,
      'Pack VIP': Infinity,
    };

    res.json({
      plan: vendorData.current_plan,
      productLimit: packLimits[vendorData.current_plan] || 0,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/subscription/upgrade', authenticate, [
  body('plan').notEmpty().withMessage('Plan requis'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

  const { plan } = req.body;
  try {
    const { error: updateError } = await supabase
      .from('vendors')
      .update({ current_plan: plan })
      .eq('auth_id', req.user.id);
    if (updateError) throw updateError;

    const paymentResponse = await axios.post(`${req.protocol}://${req.get('host')}/api/payments/create`, {
      amount: 5000, // Montant à ajuster selon le plan
      description: `Paiement pour l'abonnement ${plan}`,
      customer: {
        name: 'Utilisateur',
        email: req.user.email,
        phone: '123456789',
      },
    }, {
      headers: {
        Authorization: `Bearer ${req.headers.authorization.split(' ')[1]}`,
      },
    });

    res.json(paymentResponse.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Payment endpoints
app.post('/api/payments/create', authenticate, [
  body('amount').isFloat({ min: 100 }).withMessage('Montant minimum 100 FCFA'),
  body('description').notEmpty().withMessage('Description requise'),
  body('customer.name').notEmpty().withMessage('Nom du client requis'),
  body('customer.email').isEmail().withMessage('Email du client invalide'),
  body('customer.phone').matches(/^\d{9}$/).withMessage('Numéro de téléphone invalide (9 chiffres requis)'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { amount, description, customer } = req.body;
  const isTestMode = process.env.PAYDUNYA_TOKEN?.startsWith('test_') || false;
  const paydunyaApiUrl = isTestMode
    ? 'https://app.paydunya.com/sandbox-api/v1/checkout-invoice/create'
    : 'https://app.paydunya.com/api/v1/checkout-invoice/create';

  const payload = {
    invoice: {
      total_amount: parseFloat(amount),
      description,
      customer: {
        name: customer.name,
        email: customer.email,
        phone: customer.phone,
      },
    },
    store: { name: 'MarchéNet Afrique' },
    actions: {
      callback_url: `${process.env.FRONTEND_URL}/tableau-de-bord`,
      return_url: `${process.env.FRONTEND_URL}/tableau-de-bord`,
      cancel_url: `${process.env.FRONTEND_URL}/gérer-abonnement`,
    },
  };

  try {
    const response = await axios.post(paydunyaApiUrl, payload, {
      headers: {
        'Content-Type': 'application/json',
        'PAYDUNYA-MASTER-KEY': process.env.PAYDUNYA_MASTER_KEY,
        'PAYDUNYA-PRIVATE-KEY': process.env.PAYDUNYA_PRIVATE_KEY,
        'PAYDUNYA-TOKEN': process.env.PAYDUNYA_TOKEN,
      },
      timeout: 10000,
    });

    if (response.data.response_code !== '00') throw new Error(response.data.response_text || 'Échec de la création de la facture');
    res.status(200).json({
      success: true,
      paymentUrl: response.data.response_text,
      invoiceToken: response.data.token,
      message: 'Paiement initié avec succès',
    });
  } catch (error) {
    console.error('Erreur PayDunya API:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      message: 'Erreur lors de l\'initiation du paiement',
      error: error.response?.data || error.message,
    });
  }
});

app.get('/api/payments/status/:token', authenticate, async (req, res) => {
  const { token } = req.params;
  try {
    const response = await axios.get(`https://app.paydunya.com/api/v1/checkout-invoice/status/${token}`, {
      headers: {
        'PAYDUNYA-MASTER-KEY': process.env.PAYDUNYA_MASTER_KEY,
        'PAYDUNYA-TOKEN': process.env.PAYDUNYA_TOKEN,
      },
    });
    res.json(response.data);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Upload endpoint
app.post('/api/upload', authenticate, upload.single('image'), async (req, res) => {
  try {
    const file = req.file;
    if (!file) return res.status(400).json({ error: 'Aucun fichier uploadé' });
    const fileName = `${Date.now()}-${req.user.id}.${file.originalname.split('.').pop()}`;
    const publicUrl = `https://ton-backend.onrender.com/uploads/${fileName}`; // À remplacer par une URL réelle (Cloudinary ou autre)
    res.json({ url: publicUrl });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Démarrage du serveur
app.listen(PORT, () => {
  console.log(`Serveur démarré sur le port ${PORT} à ${new Date().toLocaleString('fr-FR', { timeZone: 'GMT' })}`);
});

app.get('/', (req, res) => {
  res.send('🚀 MarchéNet Server est en ligne !');
});
