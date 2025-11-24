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
// NOTE: express.json() removed - it consumes the body stream before proxy can forward it
// app.use(express.json()); // Parse JSON bodies
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

// API health check endpoint (for ALB routing)
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok', service: 'api-gateway' });
});

// Startup logs endpoint - generates logs on demand
app.get('/api/startup-logs', (req, res) => {
  const fs = require('fs');
  const path = require('path');
  const { execSync } = require('child_process');
  
  try {
    let logs = '';
    
    logs += '=== Service Startup Diagnostics ===\n';
    logs += `Timestamp: ${new Date().toISOString()}\n\n`;
    
    logs += '=== Environment Variables (API Gateway) ===\n';
    logs += `NODE_ENV: ${process.env.NODE_ENV || 'not set'}\n`;
    logs += `PORT: ${process.env.PORT || 'not set'}\n`;
    logs += `CORS_ORIGIN: ${process.env.CORS_ORIGIN || 'not set'}\n`;
    logs += `AUTH_SERVICE_URL: ${process.env.AUTH_SERVICE_URL || 'not set'}\n`;
    logs += `FHIR_SERVICE_URL: ${process.env.FHIR_SERVICE_URL || 'not set'}\n`;
    logs += `VISITS_SERVICE_URL: ${process.env.VISITS_SERVICE_URL || 'not set'}\n`;
    logs += `ANALYTICS_SERVICE_URL: ${process.env.ANALYTICS_SERVICE_URL || 'not set'}\n`;
    logs += `FITBIT_SERVICE_URL: ${process.env.FITBIT_SERVICE_URL || 'not set'}\n\n`;
    
    logs += '=== Service .env Files ===\n';
    const services = ['api-gateway', 'auth-service', 'fhir-api-backend', 'visits-service', 'analytics-service', 'fitbit-service'];
    for (const service of services) {
      // Try multiple possible paths
      const possiblePaths = [
        path.join(__dirname, `../../../${service}/.env`),  // From api-gateway/src
        path.join(__dirname, `../../${service}/.env`),     // One level up
        path.join(process.cwd(), `../${service}/.env`),    // From workspace root
        path.join(process.cwd(), `${service}/.env`)        // Direct from cwd
      ];
      
      let envPath = null;
      for (const p of possiblePaths) {
        if (fs.existsSync(p)) {
          envPath = p;
          break;
        }
      }
      
      if (envPath) {
        logs += `--- ${service}/.env (${envPath}) ---\n`;
        const envContent = fs.readFileSync(envPath, 'utf8');
        // Filter out sensitive data
        const filtered = envContent.split('\n')
          .filter(line => !line.match(/PASSWORD|SECRET|KEY|TOKEN/i) || line.startsWith('#'))
          .join('\n');
        logs += filtered + '\n\n';
      } else {
        logs += `--- ${service}/.env --- NOT FOUND (tried ${possiblePaths.length} paths)\n\n`;
      }
    }
    
    logs += '=== PM2 Status ===\n';
    try {
      const pm2Status = execSync('pm2 jlist', { encoding: 'utf8' });
      const processes = JSON.parse(pm2Status);
      processes.forEach(proc => {
        logs += `${proc.name}: ${proc.pm2_env.status} (restarts: ${proc.pm2_env.restart_time})\n`;
      });
    } catch (e) {
      logs += 'PM2 not available or error reading status\n';
    }
    logs += '\n';
    
    logs += '=== Network Ports ===\n';
    try {
      const netstat = execSync('netstat -tlnp 2>/dev/null | grep -E ":(3001|3002|3003|3004|3006|3008|5002|8080)" || ss -tlnp | grep -E ":(3001|3002|3003|3004|3006|3008|5002|8080)"', { encoding: 'utf8' });
      logs += netstat || 'No services listening on expected ports\n';
    } catch (e) {
      logs += 'Could not check network ports\n';
    }
    
    res.json({ success: true, logs });
  } catch (error) {
    logger.error('Error generating startup logs:', error);
    res.status(500).json({ success: false, error: error.message });
  }
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
    public: true, // Auth endpoints don't require authentication
    pathRewrite: {} // Don't rewrite the path - keep it as /api/auth
  },
  {
    url: '/api/patients',
    target: process.env.PATIENT_SERVICE_URL || 'http://localhost:8080',
    public: true, // Allow access for testing
    pathRewrite: {} // Don't rewrite the path - keep it as /api/patients
  },
  {
    url: '/api/db',
    target: process.env.PATIENT_SERVICE_URL || 'http://localhost:8080',
    public: true, // Allow access for database management
    pathRewrite: {} // Don't rewrite the path - keep it as /api/db
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
    url: '/api/visit-templates',
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
    pathRewrite: {} // Empty pathRewrite to preserve the full path
  },
  {
    url: '/api/oura',
    target: process.env.OURA_SERVICE_URL || 'http://localhost:3011',
    public: false,
    pathRewrite: {} // Empty pathRewrite to preserve the full path
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
    timeout: 120000, // 120 second timeout
    proxyTimeout: 120000, // 120 second proxy timeout
    logLevel: process.env.NODE_ENV === 'development' ? 'debug' : 'warn',
    onProxyReq: (proxyReq, req, res) => {
      // Add original user info if available
      if (req.user) {
        proxyReq.setHeader('X-User-ID', req.user.sub);
        proxyReq.setHeader('X-User-Role', req.user.role);
      }
      logger.info(`Proxying ${req.method} ${req.path} to ${route.target}`);
    },
    onProxyRes: (proxyRes, req, res) => {
      // Log response
      logger.info(`${req.method} ${req.path} -> ${route.target} returned ${proxyRes.statusCode}`);
    },
    onError: (err, req, res) => {
      // Handle proxy errors
      logger.error(`Proxy error for ${req.method} ${req.path} to ${route.target}: ${err.message}`);
      res.status(500).json({ error: 'Service unavailable', details: err.message });
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
