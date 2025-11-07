const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { createProxyMiddleware } = require('http-proxy-middleware');
const rateLimit = require('express-rate-limit');
const pino = require('pino');
const expressPino = require('express-pino-logger');
const compression = require('compression');
const { jwtCheck } = require('./middleware/auth');
require('dotenv').config();

// Initialize logger
const logger = pino({ level: process.env.LOG_LEVEL || 'info' });
const expressLogger = expressPino({ logger });

// Initialize express app
const app = express();

// Middleware
app.use(helmet()); // Security headers
app.use(cors({
  origin: true, // Allow all origins for development
  credentials: true
})); // Enable CORS
app.use(compression()); // Compress responses
app.use(express.json()); // Parse JSON bodies
app.use(expressLogger); // Request logging

// Rate limiting (disabled for development)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // Increased limit for development
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  message: 'Too many requests from this IP, please try again after 15 minutes'
});

// Apply rate limiter to all routes (with higher limit for dev)
app.use(limiter);

// Health check endpoint (no auth required)
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', service: 'api-gateway' });
});

// Comprehensive health check endpoint
app.get('/health/detailed', async (req, res) => {
  const axios = require('axios');
  const results = {
    gateway: 'ok',
    timestamp: new Date().toISOString(),
    services: {}
  };

  logger.info('=== Starting Detailed Health Check ===');

  // Test each backend service
  const servicesToTest = [
    { name: 'auth', url: process.env.AUTH_SERVICE_URL, endpoint: '/health' },
    { name: 'analytics', url: process.env.ANALYTICS_SERVICE_URL, endpoint: '/health' },
    { name: 'visits', url: process.env.VISITS_SERVICE_URL, endpoint: '/health' }
  ];

  for (const service of servicesToTest) {
    if (!service.url) {
      results.services[service.name] = { status: 'not_configured', url: 'N/A' };
      logger.warn(`Service ${service.name}: NOT CONFIGURED`);
      continue;
    }

    logger.info(`Testing ${service.name} at ${service.url}${service.endpoint}...`);

    try {
      const startTime = Date.now();
      const response = await axios.get(`${service.url}${service.endpoint}`, {
        timeout: 5000,
        validateStatus: () => true // Accept any status code
      });
      const responseTime = Date.now() - startTime;

      results.services[service.name] = {
        status: response.status === 200 ? 'healthy' : 'unhealthy',
        url: service.url,
        statusCode: response.status,
        responseTime: `${responseTime}ms`,
        data: response.data
      };

      if (response.status === 200) {
        logger.info(`✓ ${service.name}: HEALTHY (${responseTime}ms)`);
      } else {
        logger.warn(`✗ ${service.name}: UNHEALTHY - Status ${response.status} (${responseTime}ms)`);
      }
    } catch (error) {
      results.services[service.name] = {
        status: 'error',
        url: service.url,
        error: error.code || error.message,
        details: error.message
      };

      logger.error(`✗ ${service.name}: ERROR - ${error.code || error.message}`);
      logger.error(`  Details: ${error.message}`);
    }
  }

  // Determine overall health
  const allHealthy = Object.values(results.services).every(
    s => s.status === 'healthy' || s.status === 'not_configured'
  );

  const healthyCount = Object.values(results.services).filter(s => s.status === 'healthy').length;
  const totalCount = Object.keys(results.services).length;

  logger.info(`=== Health Check Complete: ${healthyCount}/${totalCount} services healthy ===`);

  const statusCode = allHealthy ? 200 : 503;
  res.status(statusCode).json(results);
});

// Service discovery (static configuration)
const serviceRoutes = [
  {
    url: '/api/auth',
    target: process.env.AUTH_SERVICE_URL || 'http://localhost:3000',
    public: true // Auth endpoints don't require authentication
  },
  {
    url: '/api/patients',
    target: process.env.PATIENT_SERVICE_URL || 'http://localhost:8080',
    public: true, // Allow access for testing
    pathRewrite: {} // Don't rewrite the path - keep it as /api/patients
  },
  {
    url: '/api/staff',
    target: process.env.STAFF_SERVICE_URL || 'http://localhost:3002',
    public: false
  },
  {
    url: '/api/medical-records',
    target: process.env.MEDICAL_RECORDS_SERVICE_URL || 'http://localhost:3003',
    public: false
  },
  {
    url: '/api/appointments',
    target: process.env.APPOINTMENTS_SERVICE_URL || 'http://localhost:3004',
    public: false
  },
  {
    url: '/api/analytics',
    target: process.env.ANALYTICS_SERVICE_URL || 'http://localhost:3005',
    public: false,
    pathRewrite: {
      '^/api/analytics': '/api/analytics'
    }
  },
  {
    url: '/api/notifications',
    target: process.env.NOTIFICATIONS_SERVICE_URL || 'http://localhost:3006',
    public: false
  },
  {
    url: '/api/visits',
    target: process.env.VISITS_SERVICE_URL || 'http://localhost:3008',
    public: false,
    pathRewrite: {} // Empty pathRewrite to preserve the full path
  },
  {
    url: '/api/tasks',
    target: process.env.VISITS_SERVICE_URL || 'http://localhost:3008',
    public: false,
    pathRewrite: {} // Empty pathRewrite to preserve the full path
  },
  {
    url: '/api/mongo',
    target: process.env.VISITS_SERVICE_URL || 'http://localhost:3008',
    public: false,
    pathRewrite: {} // Empty pathRewrite to preserve the full path
  },
  {
    url: '/api/debug',
    target: process.env.VISITS_SERVICE_URL || 'http://localhost:3008',
    public: true, // Allow debug access without auth for development
    pathRewrite: {} // Empty pathRewrite to preserve the full path
  },
  {
    url: '/api/fitbit',
    target: process.env.FITBIT_SERVICE_URL || 'http://localhost:3010',
    public: false,
    pathRewrite: {
      '^/api/fitbit': '/api/fitbit'
    }
  },
  {
    url: '/api/uploads',
    target: process.env.S3_SERVICE_URL || 'http://localhost:3009',
    public: false,
    pathRewrite: {
      '^/api/uploads': '/api/uploads'
    }
  },
  {
    url: '/api/sound-data',
    target: process.env.S3_SERVICE_URL || 'http://localhost:3009',
    public: false,
    pathRewrite: {
      '^/api/sound-data': '/api/sound-data'
    }
  }
];

// Set up proxy routes
serviceRoutes.forEach(route => {
  // Proxy options
  const options = {
    target: route.target,
    changeOrigin: true,
    pathRewrite: route.pathRewrite || {
      [`^${route.url}`]: '/api', // Default rewrite path
    },
    logLevel: process.env.NODE_ENV === 'development' ? 'debug' : 'warn',
    onProxyReq: (proxyReq, req, res) => {
      // Add original user info if available
      if (req.user) {
        proxyReq.setHeader('X-User-ID', req.user.sub);
        proxyReq.setHeader('X-User-Role', req.user.role);
      }
    },
    onProxyRes: (proxyRes, req, res) => {
      // Log response
      logger.debug(`${req.method} ${req.path} -> ${proxyRes.statusCode}`);
    },
    onError: (err, req, res) => {
      // Handle proxy errors
      logger.error(`Proxy error: ${err.message}`);
      res.status(500).json({ error: 'Service unavailable' });
    }
  };

  // Apply auth middleware for protected routes (temporarily disabled for debugging)
  const middlewares = []; // route.public ? [] : [jwtCheck];

  // Create proxy
  app.use(route.url, ...middlewares, createProxyMiddleware(options));
  logger.info(`Proxy route set up: ${route.url} -> ${route.target}`);
});

// Error handler middleware
app.use((err, req, res, next) => {
  logger.error(err);

  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ error: 'Invalid token' });
  }

  res.status(err.status || 500).json({
    error: {
      message: err.message || 'Internal Server Error',
      ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    }
  });
});

// Start server
const port = process.env.PORT || 3001;
const host = process.env.HOST || '0.0.0.0';
app.listen(port, host, () => {
  logger.info(`API Gateway listening at http://${host}:${port}`);
});

module.exports = app; // For testing
