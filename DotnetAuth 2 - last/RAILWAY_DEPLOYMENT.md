# Railway Deployment Guide for DotnetAuth API

## 🚀 Quick Deployment Steps

### 1. Prerequisites
- Railway account (sign up at [railway.app](https://railway.app))
- GitHub repository with your code
- Your current configuration values

## 🔧 Build Error Fix

If you encounter the error: `"dotnet restore" did not complete successfully: exit code: 1`

**Solution:** The project now includes two Dockerfiles:
- `Dockerfile` - Standard multi-stage build
- `Dockerfile.railway` - Railway-optimized build (recommended)

The `railway.toml` is configured to use `Dockerfile.railway` by default.

### 2. Deploy to Railway

1. **Connect to Railway**
   - Go to [railway.app](https://railway.app)
   - Click "Start a New Project"
   - Select "Deploy from GitHub repo"
   - Choose your repository

2. **Add PostgreSQL Database**
   - In your Railway project dashboard
   - Click "New Service" → "Database" → "PostgreSQL"
   - Railway will automatically create a PostgreSQL instance

3. **Configure Environment Variables**
   Go to your API service → Variables tab and add:

   ```
   DATABASE_URL=${PGDATABASE_URL}
   
   # JWT Configuration
   JWT_ISSUER=DotnetAuthAPI
   JWT_AUDIENCE=https://your-app-name.up.railway.app
   JWT_SECRET_KEY=ThisIsA32CharactersLongSecretKey!
   
   # Email Configuration (Gmail SMTP)
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USERNAME=your-smtp-username
   SMTP_PASSWORD=your-smtp-password
   SMTP_FROM_EMAIL=your-from-email
   SMTP_FROM_NAME=DotnetAuth
   
   # Google OAuth
   GOOGLE_CLIENT_ID=your-google-client-id
   GOOGLE_CLIENT_SECRET=your-google-client-secret
   
   # ReCAPTCHA
   RECAPTCHA_SITE_KEY=your-recaptcha-site-key
   RECAPTCHA_SECRET_KEY=your-recaptcha-secret-key
   ```

4. **Deploy**
   - Railway will automatically detect the Dockerfile
   - The deployment will start automatically
   - Wait for the build to complete

### 3. Post-Deployment

1. **Get Your API URL**
   - Your API will be available at: `https://your-app-name.up.railway.app`
   - Update the JWT_AUDIENCE variable with this URL

2. **Test the API**
   - Health check: `https://your-app-name.up.railway.app/health`
   - Swagger UI: `https://your-app-name.up.railway.app/swagger`

3. **Update Google OAuth Settings**
   - Go to [Google Cloud Console](https://console.cloud.google.com)
   - Update authorized redirect URIs to include your Railway domain

## 🔧 Configuration Details

### Database Connection
- Railway automatically provides `PGDATABASE_URL` environment variable
- The app automatically detects PostgreSQL and uses Npgsql
- Migrations run automatically on startup in production

### Security Notes
- All sensitive data is now in environment variables
- JWT secret should be changed to a secure 32+ character string
- Replace test CAPTCHA keys with real ones from Google reCAPTCHA

### File Storage
- Profile pictures are stored in `/app/wwwroot/profile-pictures/`
- Railway provides persistent storage for this directory

## 🐛 Troubleshooting

### Common Issues:

1. **Database Connection Errors**
   - Ensure PostgreSQL service is running
   - Check DATABASE_URL environment variable

2. **Migration Errors**
   - Check logs in Railway dashboard
   - Migrations run automatically on startup

3. **Environment Variable Issues**
   - Verify all required variables are set
   - Check for typos in variable names

### Logs
- View logs in Railway dashboard → Service → Logs tab
- Look for startup errors or database connection issues

## 📊 Monitoring

- **Health Check**: `/health` endpoint
- **Logs**: Available in Railway dashboard
- **Metrics**: Railway provides basic metrics

## 💰 Costs

- **Free Tier**: $5/month credit (sufficient for development)
- **PostgreSQL**: Included in free tier
- **Scaling**: Pay-as-you-go beyond free tier

Your API is now live and ready to use! 🎉
