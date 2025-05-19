const express = require('express');
const cors = require('cors');
const compression = require('compression');
const { createClient } = require('@supabase/supabase-js');
const NodeCache = require('node-cache');
const { body, validationResult } = require('express-validator');
require('dotenv').config();
const axios = require('axios');

const app = express();
const cache = new NodeCache({ stdTTL: 600 }); // Cache de 10 minutes

// Middleware
app.use(cors());
app.use(express.json());
app.use(compression());

// Gestion globale des erreurs
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Une erreur interne est survenue' });
});

// Initialiser Supabase
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// Route de test
app.get('/api/health', (req, res) => {
  res.status(200).json({ message: 'Serveur opérationnel' });
});

// Route pour envoyer une notification
app.post(
  '/api/notifications',
  [
    body('senderId').notEmpty().withMessage('Sender ID requis'),
    body('receiverId').notEmpty().withMessage('Receiver ID requis'),
    body('message').notEmpty().withMessage('Message requis'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { senderId, receiverId, message, target = 'all' } = req.body;
    try {
      const { error } = await supabase.from('notifications').insert({
        sender_id: senderId,
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
  }
);

// Route pour vérifier les quotas des vendeurs
app.get('/api/vendors/:vendorId/quota', async (req, res) => {
  const { vendorId } = req.params;
  const cacheKey = `quota_${vendorId}`;

  const cached = cache.get(cacheKey);
  if (cached) return res.json(cached);

  try {
    const { data: vendorData, error: vendorError } = await supabase
      .from('vendors')
      .select('pack')
      .eq('auth_id', vendorId)
      .single();

    if (vendorError) throw vendorError;

    const { data: productsData, error: productsError } = await supabase
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
      currentCount: productsData.length,
      limit: packLimits[vendorData.pack] || 0,
    };

    cache.set(cacheKey, result);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Route pour récupérer les produits paginés
app.get('/api/products', async (req, res) => {
  const { page = 1, limit = 10 } = req.query;
  const start = (page - 1) * limit;
  const end = start + parseInt(limit) - 1;

  const cacheKey = `products_${page}_${limit}`;
  const cached = cache.get(cacheKey);
  if (cached) return res.json(cached);

  try {
    const { data, error } = await supabase
      .from('products')
      .select('*')
      .range(start, end);

    if (error) throw error;

    cache.set(cacheKey, data);
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Route pour gérer les paiements PayDunya
app.post(
  '/api/payments/create',
  [
    body('vendorId').notEmpty().withMessage('Vendor ID requis'),
    body('amount').isFloat({ min: 100 }).withMessage('Montant minimum 100 FCFA'),
    body('description').notEmpty().withMessage('Description requise'),
    body('customer.name').notEmpty().withMessage('Nom du client requis'),
    body('customer.email').isEmail().withMessage('Email du client invalide'),
    body('customer.phone').matches(/^\d{9}$/).withMessage('Numéro de téléphone invalide (9 chiffres requis)'),
    body('cancel_url').optional().isURL().withMessage('URL d\'annulation invalide'),
    body('return_url').optional().isURL().withMessage('URL de retour invalide'),
    body('callback_url').optional().isURL().withMessage('URL de callback invalide'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { vendorId, amount, description, customer, cancel_url, return_url, callback_url } = req.body;
    const isTestMode = process.env.PAYDUNYA_TOKEN && process.env.PAYDUNYA_TOKEN.startsWith('test_');
    const paydunyaApiUrl = isTestMode
      ? 'https://app.paydunya.com/sandbox-api/v1/checkout-invoice/create'
      : 'https://app.paydunya.com/api/v1/checkout-invoice/create';

    const payload = {
      invoice: {
        total_amount: amount,
        description,
        customer: {
          name: customer.name,
          email: customer.email,
          phone: customer.phone,
        },
      },
      store: {
        name: 'Mon Magasin',
      },
    };

    // Ajouter les URLs de redirection si fournies
    if (cancel_url || return_url || callback_url) {
      payload.actions = {};
      if (cancel_url) payload.actions.cancel_url = cancel_url;
      if (return_url) payload.actions.return_url = return_url;
      if (callback_url) payload.actions.callback_url = callback_url;
    }

    try {
      const response = await axios.post(paydunyaApiUrl, payload, {
        headers: {
          'Content-Type': 'application/json',
          'PAYDUNYA-MASTER-KEY': process.env.PAYDUNYA_MASTER_KEY,
          'PAYDUNYA-PRIVATE-KEY': process.env.PAYDUNYA_PRIVATE_KEY,
          'PAYDUNYA-TOKEN': process.env.PAYDUNYA_TOKEN,
        },
      });

      if (response.data.response_code !== '00') {
        throw new Error(response.data.response_text || 'Échec de la création de la facture');
      }

      res.status(200).json({
        success: true,
        paymentUrl: response.data.response_text,
        invoiceToken: response.data.token,
        message: 'Paiement initié avec succès',
      });
    } catch (error) {
      console.error('Erreur PayDunya API:', error.response ? error.response.data : error.message);
      res.status(500).json({
        success: false,
        message: 'Erreur lors de l\'initiation du paiement',
        error: error.response ? error.response.data : error.message,
      });
    }
  }
);

// Route pour vérifier l'état du paiement
app.get('/api/payments/status/:invoiceToken', async (req, res) => {
  const { invoiceToken } = req.params;
  const isTestMode = process.env.PAYDUNYA_TOKEN && process.env.PAYDUNYA_TOKEN.startsWith('test_');
  const paydunyaApiUrl = isTestMode
    ? `https://app.paydunya.com/sandbox-api/v1/checkout-invoice/confirm/${invoiceToken}`
    : `https://app.paydunya.com/api/v1/checkout-invoice/confirm/${invoiceToken}`;

  try {
    const response = await axios.get(paydunyaApiUrl, {
      headers: {
        'Content-Type': 'application/json',
        'PAYDUNYA-MASTER-KEY': process.env.PAYDUNYA_MASTER_KEY,
        'PAYDUNYA-PRIVATE-KEY': process.env.PAYDUNYA_PRIVATE_KEY,
        'PAYDUNYA-TOKEN': process.env.PAYDUNYA_TOKEN,
      },
    });

    if (response.data.response_code !== '00') {
      throw new Error(response.data.response_text || 'Échec de la vérification du statut');
    }

    res.status(200).json({
      success: true,
      status: response.data.status,
      details: response.data,
      message: 'Statut du paiement récupéré avec succès',
    });
  } catch (error) {
    console.error('Erreur PayDunya API:', error.response ? error.response.data : error.message);
    res.status(500).json({
      success: false,
      message: 'Erreur lors de la vérification du statut',
      error: error.response ? error.response.data : error.message,
    });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Serveur démarré sur le port ${PORT} à ${new Date().toLocaleString('fr-FR', { timeZone: 'GMT' })}`));