defmodule Tds.FedAuth do
  ## Packet Size
  @tds_pack_data_size 4088
  @tds_pack_header_size 8
  @tds_pack_size @tds_pack_header_size + @tds_pack_data_size
  @tds_feature_ext_terminator 0xFF

  import Tds.Utils

  def encode_login7(opts) do
    tds_version = <<0x04, 0x00, 0x00, 0x74>>
    message_size = <<@tds_pack_size::little-size(4)-unit(8)>>
    client_prog_ver = <<0x04, 0x00, 0x00, 0x07>>

    [_, pid, _] = "#{inspect(self())}" |> String.split(".")
    current_pid = pid |> String.to_integer()
    client_pid = <<current_pid::little-size(4)-unit(8)>>

    connection_id = <<0x00::size(32)>>
    option_flags_1 = <<0xF0>>
    option_flags_2 = <<0x00>>
    type_flags = <<0x00>>

    # Enable:
    # fUnknownCollationHandling
    # fExtension
    option_flags_3 = <<0x18>>

    client_time_zone = <<0x00, 0x00, 0x00, 0x00>>
    client_lcid = <<0x09, 0x04, 0x00, 0x00>>

    login_a =
      tds_version <>
        message_size <>
        client_prog_ver <>
        client_pid <>
        connection_id <>
        option_flags_1 <>
        option_flags_2 <>
        type_flags <> option_flags_3 <> client_time_zone <> client_lcid

    # Add 4 byte for message length
    offset_start = byte_size(login_a) + 4

    {:ok, hostname} = :inet.gethostname()
    hostname = String.Chars.to_string(hostname)
    hostname_ucs = to_little_ucs2(hostname)

    app_name = Node.self() |> Atom.to_string()
    app_name_ucs = to_little_ucs2(app_name)

    servername = opts[:hostname]
    servername_ucs = to_little_ucs2(servername)

    clt_int_name = "tdsx"
    clt_int_name_ucs = to_little_ucs2(clt_int_name)
    database = opts[:database] || ""

    database_ucs = to_little_ucs2(database)

    # data start in the offset login_a(36) + reserved_offset(58) = 94
    curr_offset = offset_start + 58
    ibHostName = <<curr_offset::little-size(16)>>
    # we use hostname because we need write the lengh in chars
    cchHostName = <<String.length(hostname)::little-size(16)>>

    # the curr_offset grown in the ucs2 byte, the ucs2 use double byte to represent a char
    curr_offset = curr_offset + byte_size(hostname_ucs)

    ibUserName = <<curr_offset::little-size(16)>>
    cchUserName = <<0::little-size(16)>>

    ibPassword = <<curr_offset::little-size(16)>>
    cchPassword = <<0::little-size(16)>>
    # =======================

    ibAppName = <<curr_offset::little-size(16)>>
    cchAppName = <<String.length(app_name)::little-size(16)>>
    curr_offset = curr_offset + byte_size(app_name_ucs)

    ibServerName = <<curr_offset::little-size(16)>>
    cchServerName = <<String.length(servername)::little-size(16)>>
    curr_offset = curr_offset + byte_size(servername_ucs)

    # ==================
    auth_type = "azure-active-directory-password"

    feature_ext =
      case auth_type do
        "azure-active-directory-password" ->
          id = <<0x02::size(8)>>
          bFedAuthLibrary = <<0x02::size(7)>>
          fFedAuthEcho = <<0x01::size(1)>>
          options = <<bFedAuthLibrary::bitstring, fFedAuthEcho::bitstring>>
          workFlow = <<0x01>>
          data = options <> workFlow
          dataLen = <<byte_size(data)::little-size(32)>>
          id <> dataLen <> data <> <<@tds_feature_ext_terminator>>
      end

    ibExtension = <<curr_offset::little-size(16)>>
    cbExtension = <<4::little-size(16)>>
    feature_ext_offset = <<curr_offset + 4::little-size(32)>>
    curr_offset = curr_offset + byte_size(feature_ext)

    ibCltIntName = <<curr_offset::little-size(16)>>
    cchCltIntName = <<4::little-size(16)>>
    curr_offset = curr_offset + 4 * 2

    ibLanguage = <<0::size(16)>>
    cchLanguage = <<0::size(16)>>

    ibDatabase = <<curr_offset::little-size(16)>>

    cchDatabase = <<String.length(database)::little-size(16)>>

    clientID = <<1, 2, 3, 4, 5, 6>>

    ibSSPI = <<0::size(16)>>
    cbSSPI = <<0::size(16)>>

    ibAtchDBFile = <<0::size(16)>>
    cchAtchDBFile = <<0::size(16)>>

    ibChangePassword = <<0::size(16)>>
    cchChangePassword = <<0::size(16)>>

    cbSSPILong = <<0::size(32)>>

    login_data =
      hostname_ucs <>
        app_name_ucs <>
        servername_ucs <>
        feature_ext_offset <>
        feature_ext <>
        clt_int_name_ucs <>
        database_ucs

    # Here add ibExtension and cbExtension
    offset =
      ibHostName <>
        cchHostName <>
        ibUserName <>
        cchUserName <>
        ibPassword <>
        cchPassword <>
        ibAppName <>
        cchAppName <>
        ibServerName <>
        cchServerName <>
        ibExtension <>
        cbExtension <>
        ibCltIntName <>
        cchCltIntName <>
        ibLanguage <>
        cchLanguage <>
        ibDatabase <>
        cchDatabase <>
        clientID <>
        ibSSPI <>
        cbSSPI <>
        ibAtchDBFile <>
        cchAtchDBFile <> ibChangePassword <> cchChangePassword <> cbSSPILong

    login7 = login_a <> offset <> login_data

    login7_len = byte_size(login7) + 4
    data = <<login7_len::little-size(32)>> <> login7

    Tds.Messages.encode_packets(0x10, data)
  end

  def encode_fedauth(opts) do
    access_token =
      Map.get(opts, "access_token")
      |> to_little_ucs2()

    token_len = byte_size(access_token)
    data_len = 4 + token_len

    data =
      <<data_len::little-size(32), token_len::little-size(32),
        access_token::binary>>

    Tds.Messages.encode_packets(0x08, data)
  end

  def parse_featureextack(<<2::size(8), 0::size(32), 0xFF, tail::binary>>) do
    # FeatureExtAck response without data when is ok
    {{:featureextack, :ok}, tail}
  end

  def parse_featureextack(
        <<2::size(8), l::size(32), data::binary-size(l), tail::binary>>
      ) do
    {{:featureextack, data}, tail}
  end

  def parse_featureextack(
        <<featureId::size(8), dataLen::size(32), data::binary>>
      ) do
    raise "featureExt #{featureId} not implemente"
  end

  def parse_info(
        <<_dataLen::little-size(32), countOfInfoIDs::little-size(32),
          tail::binary>> = _data
      ) do
    parse_info(tail, countOfInfoIDs)
  end

  defp parse_info(data, countOfInfoIDs) do
    <<id::size(8), dataLen::little-size(32), dataOffset::little-size(32),
      tail::binary>> = data

    parse_info(tail, countOfInfoIDs, [{id, dataLen, dataOffset}])
  end

  defp parse_info(data, countOfInfoIDs, meta)
       when length(meta) < countOfInfoIDs do
    <<id::size(8), dataLen::little-size(32), dataOffset::little-size(32),
      tail::binary>> = data

    parse_info(tail, countOfInfoIDs, meta ++ [{id, dataLen, dataOffset}])
  end

  defp parse_info(data, countOfInfoIDs, meta)
       when length(meta) == countOfInfoIDs do
    parse_info(data, nil, meta, [])
  end

  defp parse_info(
         data,
         _countOfInfoIDs,
         [{id, dataLen, _dataOffset} | rest_meta] = meta,
         fragments
       )
       when length(meta) > 0 do
    case id do
      2 ->
        <<fragment::binary-size(dataLen), tail::binary>> = data

        parse_info(
          tail,
          nil,
          rest_meta,
          fragments ++ [{:spn, :unicode.characters_to_binary(fragment)}]
        )

      1 ->
        <<fragment::binary-size(dataLen), tail::binary>> = data

        parse_info(
          tail,
          nil,
          rest_meta,
          fragments ++ [{:stsurl, :unicode.characters_to_binary(fragment)}]
        )

      _ ->
        parse_info(data, nil, rest_meta, fragments)
    end
  end

  defp parse_info(_data, _countOfInfoIDs, _meta, fragments) do
    fragments
  end

  def get_credentials(fedauthinfo, %{opts: opts} = s) do
    {:fedauth, module, params} = Keyword.get(opts, :authentication)

    params =
      Enum.filter(opts, fn {key, _} ->
        Enum.member?([:username, :password], key)
      end) ++ fedauthinfo ++ params

    case module.get_token(params) do
      {:ok, credentials} ->
        {:ok, %{s | fedauth_credentials: credentials}}

      err ->
        err
    end
  end

  def get_credentials(_, _),
    do: {:error, "invalid information, cannot get credentials"}
end
