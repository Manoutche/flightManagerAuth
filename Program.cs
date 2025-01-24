var builder = WebApplication.CreateBuilder(args);
// Ajouter une politique CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAngularApp", policy =>
    {
        policy.WithOrigins("http://localhost:4200") // L'origine de votre application Angular
              .AllowAnyHeader() // Autoriser tous les en-têtes HTTP
              .AllowAnyMethod(); // Autoriser toutes les méthodes HTTP (GET, POST, etc.)
    });
});
builder.Services.AddControllers();
var app = builder.Build();
// Utiliser la politique CORS
app.UseCors("AllowAngularApp");
app.MapControllers();
app.Run();
