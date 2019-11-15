Configuration = configuration;
            var contentRoot = configuration.GetValue<string>(WebHostDefaults.ContentRootKey);
            
            var dom = new ConfigurationBuilder()
                        .AddJsonFile(contentRoot+@"\Configs\BrandMapping.json", optional: true, reloadOnChange: true);
            configuration.Bind(dom);
            //Configuration = dom.Build(dom);
            var t = Configuration["AuthConfig:SecretKey"];
			
			
			public Startup(IConfiguration configuration, IHostingEnvironment env)
{
     var contentRoot = env.ContentRootPath;
}
			
			
Host.CreateDefaultBuilder(args).ConfigureAppConfiguration((hostingContext, config) =>
            {
                var ctx=hostingContext.Configuration;
                //config.AddJsonFile(, optional: true, reloadOnChange: true);
            })