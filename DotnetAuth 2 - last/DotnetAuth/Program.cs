using DotnetAuth.Domain.Entities;
using DotnetAuth.Exceptions;
using DotnetAuth.Extensions;
using DotnetAuth.Infrastructure.Context;
using DotnetAuth.Infrastructure.Mapping;
using DotnetAuth.Infrastructure.Seeding;
using DotnetAuth.Infrastructure.Validators;
using DotnetAuth.Middleware;
using DotnetAuth.Service;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// Add Distributed Cache for token blacklist
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSingleton<ITokenBlacklistService, TokenBlacklistService>();

builder.Services.AddHttpContextAccessor();

// Register Email Service
builder.Services.AddScoped<IEmailService, SmtpEmailService>();
builder.Services.AddScoped<ProfilePictureSeeder>();

// Register CAPTCHA Service
builder.Services.AddHttpClient("CaptchaClient");
builder.Services.AddScoped<ICaptchaService, CaptchaServiceImpl>();

builder.Services.AddExceptionHandler<GlobalExceptionHandler>();

builder.Services.AddProblemDetails();

builder.Services.AddControllers();

// Configure static files
builder.Services.AddDirectoryBrowser();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "DotnetAuth API",
        Version = "v1.0",
        Description = @"
## Comprehensive Authentication & User Management API

This API provides a complete authentication and user management solution with the following features:

### 🔐 **Authentication Features**
- **User Registration** with email verification
- **Secure Login** with JWT tokens
- **Two-Factor Authentication (2FA)** support
- **Password Reset** functionality
- **External Authentication** (Google OAuth)
- **Token Management** with blacklisting support

### 👤 **User Management**
- **Profile Management** with picture upload
- **Account Settings** (email, phone number changes)
- **Activity Logging** and login history
- **Role-based Access Control** (Admin, Doctor, Patient)

### 🛡️ **Security Features**
- **JWT Token Authentication** with refresh tokens
- **CAPTCHA Protection** for registration and login
- **Account Lockout** after failed attempts
- **Secure Password Policies** (12+ characters, complexity requirements)
- **Token Blacklisting** for secure logout

### 📱 **Additional Features**
- **Phone Number Verification**
- **Email Change Verification**
- **Account Activity Tracking**
- **Profile Picture Management**

### 🔧 **Technical Details**
- Built with **.NET 9.0** and **ASP.NET Core**
- Uses **Entity Framework Core** with SQL Server
- Implements **AutoMapper** for object mapping
- Comprehensive **logging** and **error handling**
",
        Contact = new OpenApiContact
        {
            Name = "API Support",
            Email = "support@dotnetauth.com",
            Url = new Uri("https://github.com/yourusername/dotnetauth")
        },
        License = new OpenApiLicense
        {
            Name = "MIT License",
            Url = new Uri("https://opensource.org/licenses/MIT")
        }
    });

    // Include XML comments
    var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    if (File.Exists(xmlPath))
    {
        c.IncludeXmlComments(xmlPath);
    }

    // Add security definition for JWT Bearer tokens
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = @"
**JWT Authorization header using the Bearer scheme.**

Enter your JWT token in the text input below.

Example: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`

**Note:** Do not include the word 'Bearer' - it will be added automatically."
    });

    // Add security requirement
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                },
                Scheme = "oauth2",
                Name = "Bearer",
                In = ParameterLocation.Header,
            },
            new List<string>()
        }
    });

    // Configure Swagger to use enum names instead of values
    c.UseInlineDefinitionsForEnums();

    // Add operation filters for better documentation
    c.EnableAnnotations();

    // Group endpoints by tags
    c.TagActionsBy(api => new[] { api.GroupName ?? api.ActionDescriptor.RouteValues["controller"] });
    c.DocInclusionPredicate((name, api) => true);
});

// Adding Database context
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    var connectionString = builder.Configuration.GetConnectionString("ProductionConnection")
                          ?? builder.Configuration.GetConnectionString("C")
                          ?? builder.Configuration.GetConnectionString("DefaultConnection");

    if (connectionString.Contains("postgresql://") || connectionString.Contains("postgres://"))
    {
        // Use PostgreSQL for production deployments
        options.UseNpgsql(connectionString);
    }
    else
    {
        // Use SQL Server for local development
        options.UseSqlServer(connectionString);
    }
});

// Adding Identity with enhanced security settings
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options => {
    // Password settings
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 12;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;

    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    // User settings
    options.User.RequireUniqueEmail = true;

    // SignIn settings
    options.SignIn.RequireConfirmedEmail = true;
    options.SignIn.RequireConfirmedAccount = true;

    // Default password validation will be handled by CustomPasswordValidator
    options.Password.RequiredUniqueChars = 4;
})
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders()
    .AddPasswordValidator<CustomPasswordValidator<ApplicationUser>>();

// Adding Services
builder.Services.AddScoped<IUserServices, UserServiceImpl>();
builder.Services.AddScoped<ITokenService, ToekenServiceImple>();
builder.Services.AddScoped<ICurrentUserService, CurrentUserService>();
builder.Services.AddScoped<IProfilePictureService, ProfilePictureService>();
builder.Services.AddScoped<IActivityLoggingService, ActivityLoggingService>();
builder.Services.AddScoped<ITwoFactorService, TwoFactorServiceImpl>();
builder.Services.AddScoped<IExternalAuthService, ExternalAuthServiceImpl>();

// Regsitering AutoMapper
builder.Services.AddAutoMapper(typeof(MappingProfile).Assembly);

// Adding Jwt from extension method
builder.Services.ConfigureIdentity();
builder.Services.ConfigureJwt(builder.Configuration);
builder.Services.ConfigureCors();

var app = builder.Build();

// Run database migrations and initialize data
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

    // Apply pending migrations automatically in production
    if (app.Environment.IsProduction())
    {
        await context.Database.MigrateAsync();
    }

    // Initialize roles and default profile picture
    await RoleInitializer.InitializeRolesAsync(app.Services);
    var pictureSeeder = scope.ServiceProvider.GetRequiredService<ProfilePictureSeeder>();
    await pictureSeeder.SeedAsync();
}

// Ensure wwwroot directory exists and set it as WebRootPath
var wwwrootPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot");
if (!Directory.Exists(wwwrootPath))
    Directory.CreateDirectory(wwwrootPath);

// Create necessary directories for profile pictures
var profilePicturesPath = Path.Combine(wwwrootPath, "profile-pictures");
var defaultPicturesPath = Path.Combine(profilePicturesPath, "defaults");

if (!Directory.Exists(profilePicturesPath))
    Directory.CreateDirectory(profilePicturesPath);
if (!Directory.Exists(defaultPicturesPath))
    Directory.CreateDirectory(defaultPicturesPath);

// Configure the HTTP request pipeline.
// if (app.Environment.IsDevelopment())
//{
    app.UseSwagger();
    app.UseSwaggerUI();
//}

app.UseStaticFiles(); // This line should be before UseRouting
app.UseHttpsRedirection();
app.UseExceptionHandler();
app.UseRouting();
app.UseCors("CorsPolicy");

// Add JWT blacklist middleware before authorization
app.UseJwtBlacklist();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// Add health check endpoint
app.MapHealthChecks("/health");

app.Run();
