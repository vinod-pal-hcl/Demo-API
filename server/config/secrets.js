/**
 * ==================================================================================
 * INTENTIONALLY VULNERABLE CODE - SAST TESTING PROJECT
 * ==================================================================================
 * This configuration file contains FAKE hardcoded secrets for SAST testing:
 * - Cloud provider API keys (AWS, Azure, GCP)
 * - Payment gateway keys (Stripe, PayPal)
 * - Social media API tokens
 * - Database connection strings
 * - JWT secrets
 * - SSH/RSA private keys
 * 
 * ALL CREDENTIALS ARE FAKE - FOR TESTING PURPOSES ONLY
 * DO NOT USE IN PRODUCTION
 * ==================================================================================
 */

module.exports = {
  // ===== AWS CREDENTIALS - CRITICAL =====
  aws: {
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    region: 'us-east-1',
    s3Bucket: 'my-secret-bucket',
    lambdaArn: 'arn:aws:lambda:us-east-1:123456789012:function:MyFunction'
  },

  // ===== AZURE CREDENTIALS - CRITICAL =====
  azure: {
    subscriptionId: '12345678-1234-1234-1234-123456789012',
    clientId: '12345678-1234-1234-1234-123456789012',
    clientSecret: 'MyAzureClientSecret123!',
    tenantId: '12345678-1234-1234-1234-123456789012',
    storageConnectionString: 'DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey=abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567ABC890DEF123GHI456JKL789MNO==;EndpointSuffix=core.windows.net'
  },

  // ===== GCP CREDENTIALS - CRITICAL =====
  gcp: {
    projectId: 'my-gcp-project-12345',
    privateKey: '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA2mKqH...\n-----END RSA PRIVATE KEY-----',
    clientEmail: 'my-service-account@my-gcp-project-12345.iam.gserviceaccount.com',
    apiKey: 'AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI'
  },

  // ===== STRIPE CREDENTIALS - CRITICAL =====
  stripe: {
    publishableKey: 'pk_live_51HqLyjWDarjtT1zdp7dcXYZ123456789',
    secretKey: 'sk_live_51HqLyjWDarjtT1zdp7dcXYZ123456789',
    webhookSecret: 'whsec_1234567890abcdefghijklmnopqrstuvwxyz'
  },

  // ===== PAYPAL CREDENTIALS - CRITICAL =====
  paypal: {
    clientId: 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz',
    clientSecret: 'EFGHIjklmnopQRSTuvwxYZ1234567890abcdefghijklmnop',
    webhookId: '1234567890ABCDEFGHIJ'
  },

  // ===== OAUTH2 SECRETS - CRITICAL =====
  oauth: {
    google: {
      clientId: '123456789012-abcdefghijklmnopqrstuvwxyz123456.apps.googleusercontent.com',
      clientSecret: 'GOCSPX-abcdefghijklmnopq'
    },
    facebook: {
      appId: '1234567890123456',
      appSecret: 'abcdef1234567890abcdef1234567890'
    },
    github: {
      clientId: 'Iv1.1234567890abcdef',
      clientSecret: '1234567890abcdef1234567890abcdef12345678'
    }
  },

  // ===== DATABASE CREDENTIALS - CRITICAL =====
  database: {
    mongodb: {
      uri: 'mongodb+srv://admin:SuperSecretPassword123!@cluster0.abcde.mongodb.net/production?retryWrites=true&w=majority',
      password: 'SuperSecretPassword123!'
    },
    mysql: {
      host: 'prod-mysql-server.example.com',
      username: 'root',
      password: 'MySQLRootP@ssw0rd!',
      database: 'production'
    },
    postgresql: {
      connectionString: 'postgresql://admin:PostgresP@ss123!@prod-db.example.com:5432/production'
    },
    redis: {
      url: 'redis://:RedisP@ssword123@redis-server.example.com:6379'
    }
  },

  // ===== JWT AND SESSION SECRETS - CRITICAL =====
  jwt: {
    secret: 'my-super-secret-jwt-signing-key-that-should-never-be-hardcoded',
    refreshSecret: 'my-refresh-token-secret-key-12345',
    accessTokenExpiry: '15m',
    refreshTokenExpiry: '7d'
  },
  session: {
    secret: 'session-secret-key-1234567890',
    cookieSecret: 'cookie-signing-secret-key'
  },

  // ===== API KEYS - CRITICAL =====
  apiKeys: {
    sendgrid: 'SG.abcdefghijklmnopqrstuvwxyz.1234567890ABCDEFGHIJKLMNOPQRSTUV',
    twilio: {
      accountSid: 'AC1234567890abcdef1234567890abcdef',
      authToken: '1234567890abcdef1234567890abcdef'
    },
    mailchimp: 'abcdef1234567890abcdef1234567890-us1',
    slack: {
      botToken: 'xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx',
      webhookUrl: 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX'
    },
    openai: 'sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEF',
    algolia: {
      appId: 'ABCDEFGHIJ',
      apiKey: '1234567890abcdef1234567890abcdef'
    }
  },

  // ===== SSH/RSA KEYS - CRITICAL =====
  ssh: {
    privateKey: `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHxLl3TBzPbqOMxGrzB5
VT7FTsGOZ4TWN7PmLT9XjP+E8M/pqFxxsMkLxFf3zz8snufN1R7F8a0j3JJvT0XL
B8diRlOlSmPyWj1FXGV8GmV+d9bQ5vPvRTmhiuM8Gj1l5VaEbqR1Ei+QIJNaRZ7L
SuLQc8NmLJdBh3K3Wa7D+0UjLW0Gcgj8zKwKGNxjtK/FnvqNl5H8f6fMz7JvWk9j
C54nPDDsGO5z9lCcD1KPFNBPV1qUw9HZo8cCzFmFuGw8eDdSjA4P2Z3h1E7sL0Bs
ExAMPLE_FAKE_KEY_FOR_TESTING_ONLY
-----END RSA PRIVATE KEY-----`,
    publicKey: 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...'
  },

  // ===== ENCRYPTION KEYS - CRITICAL =====
  encryption: {
    aesKey: '12345678901234567890123456789012',
    aesIv: '1234567890123456',
    hmacSecret: 'hmac-secret-key-for-signing-data',
    salt: 'static-salt-value-should-be-random'
  },

  // ===== ADMIN CREDENTIALS - CRITICAL =====
  admin: {
    username: 'admin',
    password: 'Admin@123!',
    email: 'admin@example.com',
    apiKey: 'admin-api-key-1234567890'
  },

  // ===== THIRD PARTY SERVICES - HIGH =====
  services: {
    sentry: {
      dsn: 'https://abcdef1234567890@o123456.ingest.sentry.io/1234567'
    },
    newrelic: {
      licenseKey: 'abcdef1234567890abcdef1234567890abcdef12'
    },
    datadog: {
      apiKey: 'abcdef1234567890abcdef1234567890'
    },
    elasticsearch: {
      cloudId: 'my-cluster:dXMtZWFzdC0xLmF3cy5mb3VuZC5pbzo0NDMkYWJjZGVm',
      username: 'elastic',
      password: 'ElasticP@ss123!'
    }
  },

  // ===== FEATURE FLAGS WITH SECRETS - MEDIUM =====
  features: {
    debugMode: true,  // Debug enabled in config - VULNERABILITY
    bypassAuth: true,  // Auth bypass flag - VULNERABILITY
    adminOverride: true,
    showStackTraces: true  // Exposing stack traces - VULNERABILITY
  }
};
