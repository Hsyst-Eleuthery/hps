using Hps.Cli.Core;

var app = new CliApplication();
return await app.RunAsync(args, CancellationToken.None);
