defmodule FedAuthTest do
  use ExUnit.Case, async: true

  @tag :manual
  test "azure sql federate authentication with user and password" do
    opts = [
      queue_target: 5000,
      ssl: true,
      hostname: "azuresqlinstance.database.windows.net",
      username: "user@domain.com",
      password: "password",
      database: "database_name",
      authentication: {
        :fedauth,
        AzureAuthenticationLibrary,
        [
          domain: "domain.com",
          type: "azure-active-directory-password"
        ]
      },
      show_sensitive_data_on_connection_error: true,
      trace: true
    ]

    assert {:ok, _state} = Tds.Protocol.connect(opts)
  end
end
