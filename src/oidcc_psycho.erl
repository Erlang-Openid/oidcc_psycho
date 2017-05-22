-module(oidcc_psycho).

-export([
         oidcc/1,
         oidcc_app/0]
       ).

-define(COOKIE, <<"oidcc_session">>).

oidcc(_NextApp) ->
    ok.

oidcc_app() ->
    fun perform_oidcc/1.


perform_oidcc(Env0) ->
    { {_, _, QsList} , Env1} = psycho_utils:ensure_parsed_request_path(Env0),
    {_, Env} = psycho_utils:ensure_parsed_cookie(Env1),
    Provider = validate_provider(proplists:get_value("provider", QsList)),
    login_or_redirect(Provider, Env).


login_or_redirect(undefined, Env) ->
    perform_oidcc_login(Env);
login_or_redirect(ProviderId, Env) ->
    redirect_to_provider(ProviderId, Env).


perform_oidcc_login(Env) ->
    {_, _, QsList} = psycho:env(parsed_request, Env),
    SessionId = try_binary(proplists:get_value("state", QsList)),
    handle_oidc_session(oidcc_session_mgr:get_session(SessionId), Env).

redirect_to_provider(bad_provider, Env) ->
    Desc = <<"unknown provider id">>,
    handle_fail(bad_request, Desc, Env);
redirect_to_provider(ProviderId, Env) ->
    {ok, Session} = oidcc_session_mgr:new_session(ProviderId),
    CookieDefault = application:get_env(oidcc, use_cookie, false),
    {_, _, QsList} = psycho:env(parsed_request, Env),
    ReqUseCookie = try_binary(proplists:get_value("use_cookie", QsList, false)),
    UseCookie = ReqUseCookie or CookieDefault,
    UserAgent = try_binary(psycho:env_header("user-agent", Env)),
    ok = oidcc_session:set_user_agent(UserAgent, Session),
    %% ok = oidcc_session:set_peer_ip(PeerIp, Session),
    ok = oidcc_session:set_client_mod(ClientModId, Session),
    {ok, Url} = oidcc:create_redirect_for_session(Session),
    CookieUpdate = cookie_update_if_requested(UseCookie, Session),
    Redirect = {redirect, Url},
    Updates = [CookieUpdate, Redirect],
    {ok, Req2} = apply_updates(Updates, Req),
    {ok, Req2, State}.


handle_oidc_session({ok, Session}, Env) ->
    get = method_to_atom(psycho:env(request_method, Env)),
    Error = try_binary(proplists:get_value("error", Env)),
    login_or_error(Error, [{oidc_session, Session} | Env]);
handle_oidc_session({error, Reason}, Env) ->
    Desc = list_to_binary(io_lib:format("session not found: ~s", [Reason])),
    handle_fail(session_not_found, Desc, Env).


login_or_error(undefined, Env) ->
    Session = psycho:env(oidc_session, Env),
    {_, _, QsList} = psycho:env(parsed_request, Env),
    AuthCode = try_binary(proplists:get_value("code", QsList)),
    UserAgent = try_binary(psycho:env_header("user-agent", Env)),
    Cookies = psycho:env(parsed_cookie, Env),
    CookieData = try_binary(proplists:get_value(?COOKIE, Cookies)),
    {ok, Provider} = oidcc_session:get_provider(Session),
    {ok, Pkce} = oidcc_session:get_pkce(Session),
    {ok, Nonce} = oidcc_session:get_nonce(Session),
    {ok, Scope} = oidcc_session:get_scopes(Session),
    IsUserAgent = oidcc_session:is_user_agent(UserAgent, Session),
    CheckUserAgent = application:get_env(oidcc, check_user_agent, true),
    CookieValid = oidcc_session:is_cookie_data(CookieData, Session),
    UserAgentValid = ((not CheckUserAgent) or IsUserAgent),
    Config = #{nonce => Nonce,
               pkce => Pkce,
               scope => Scope
              },
    TokenResult = oidcc:retrieve_and_validate_token(AuthCode, Provider, Config),
    handle_token_validation(TokenResult, UserAgentValid, CookieValid, Env);
login_or_error(Error, Env) ->
    handle_fail(oidc_provider_error, Error, Env).


handle_token_validation({ok, Token}, true, true, Env) ->
    %% {ok, VerifiedToken} = add_configured_info(Token, Provider, Cookies),
    Session = psycho:env(oidc_session, Env),
    ClientModId = default,
    ok = oidcc_session:close(Session),
    {ok, UpdateList} = oidcc_client:succeeded(Token, ClientModId),
    apply_updates(UpdateList, [{oidc_response_header, []} | Env ]);
handle_token_validation({ok, _}, false, _, Env) ->
    UserAgent = try_binary(psycho:env_header("user-agent", Env)),
    handle_fail(bad_user_agent, UserAgent, Env);
handle_token_validation({ok, _}, _, false, Env) ->
    Cookies = psycho:env(parsed_cookie, Env),
    CookieData = try_binary(proplists:get_value(?COOKIE, Cookies)),
    handle_fail(bad_cookie, CookieData, Env);
handle_token_validation(TokenError, _, _, Env) ->
    handle_fail(token_invalid, TokenError, Env).


handle_fail(Error, Description, Env) ->
    ClientModId = default,
    {ok, UpdateList} = oidcc_client:failed(Error, Description, ClientModId),
    apply_updates(UpdateList, [{oidc_response_header, []} | Env ]).

validate_provider(undefined) ->
    undefined;
validate_provider(ProviderId) ->
    Id = list_to_binary(ProviderId),
    return_provider_if_exists(oidcc:get_openid_provider_info(Id)).

return_provider_if_exists({ok, #{id := Id}}) ->
    Id;
return_provider_if_exists(_) ->
    bad_provider.


method_to_atom("GET") ->
    get;
method_to_atom("POST") ->
    post;
method_to_atom(_) ->
    unknown.

try_binary(Binary) when is_binary(Binary) ->
    Binary;
try_binary(List) when is_list(List)  ->
    list_to_binary(List);
try_binary(Other) ->
    Other.

apply_updates([], Env) ->
    {ok, Env};
apply_updates([{redirect, Url}], Env) ->
    Header = psycho:env(oidc_response_header, Env),
    {{302, ""}, [{"Location", Url} | Header], ""};
apply_updates([{cookie, Name, Data, Options} | T], Env) ->
    HeaderList = psycho:env(oidc_response_header, Env),
    Header = psycho_utils:cookie_header(Name, Data, Options),
    Result = [ Header | HeaderList ],
    apply_updates(T, psycho:set_env({oidc_response_header, Result}, Env));
apply_updates([{none} | T], Req) ->
    apply_updates(T, Req).
