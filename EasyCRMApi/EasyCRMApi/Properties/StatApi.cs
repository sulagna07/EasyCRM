

===============================================================================================
<?xml version="1.0" encoding="utf-8"?>
<configuration>
<system.webServer>
  <rewrite>
    <rules>
      <rule name="Angular Routes" stopProcessing="true">
        <match url="^satafclient/" />
        <conditions logicalGrouping="MatchAll">
          <add input="{REQUEST_FILENAME}" matchType="IsFile" negate="true" />
          <add input="{REQUEST_FILENAME}" matchType="IsDirectory" negate="true" />
        </conditions>
        <action type="Rewrite" url="/satafclient/" />
      </rule>
    </rules>
  </rewrite>
</system.webServer>

</configuration>
