# Backend

To run Backend, 

```dotnet watch -lp https```
## Document generation 
[v1.json](./openapi/v1.json) is automatically generated at build time.(But currently not work...)

Reference :
- [microsoft docs](https://learn.microsoft.com/ja-jp/aspnet/core/fundamentals/openapi/aspnetcore-openapi?view=aspnetcore-9.0&tabs=visual-studio)
## Swagger UI
We use [NSwag](https://github.com/RicoSuter/NSwag) to generate Swagger UI. Please visit /swagger endpoint.
Reference :
- [Swashbuckle vs NSwag](https://devlog.mescius.jp/asp-net-core-web-api-nswag/)
- [nuget](https://www.nuget.org/packages/NSwag.AspNetCore/)

# Data
## Migration 
```dotnet ef migrations add InitialCreate```
