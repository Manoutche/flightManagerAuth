## Local Runing

dotnet run

## Published

dotnet publish -c Release -o "C:\Projet dev\activeDirectoryauthAPI"

## web.config example

<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <!-- Gestionnaire ASP.NET Core -->
    <handlers>
      <add name="aspNetCore" path="*" verb="*" modules="AspNetCoreModuleV2" resourceType="Unspecified" />
    </handlers>

    <!-- Paramètres ASP.NET Core -->
    <aspNetCore processPath="dotnet" 
                arguments=".\flightManagerAuth.dll" 
                stdoutLogEnabled="true" 
                stdoutLogFile=".\logs\stdout" 
                hostingModel="inprocess">
      <environmentVariables>
        <environmentVariable name="ASPNETCORE_ENVIRONMENT" value="Production" />
        <environmentVariable name="LDAP_DOMAIN" value="local.com" />
        <environmentVariable name="LDAP_SERVER" value="toncontroleurAD.ton-domaine.local" />
      </environmentVariables>
    </aspNetCore>
  </system.webServer>
</configuration>