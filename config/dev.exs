use Mix.Config

config :tds,
  opts: [hostname: "nitrox", username: "sa", password: "some!Password", database: "test", ssl: true, ssl_opts: [certfile: "/Users/mjaric/prj/github/tds/mssql.pem", keyfile: "/Users/mjaric/prj/github/tds/mssql.key"]]
