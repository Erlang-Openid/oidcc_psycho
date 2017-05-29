-module(basic_client_app).
-behaviour(application).

-export([start/2]).
-export([stop/1]).

start(_, _) ->
    ConfigEndpoint = <<"https://accounts.google.com/.well-known/openid-configuration">>,
    LocalEndpoint = <<"http://localhost:8080/oidc">>,
    Config = #{
      id => <<"google">>,
      client_id => <<"65375832888-m99kcr0vu8qq95h588b1rhi52ei234qo.apps.googleusercontent.com">>,
      client_secret =>  <<"MEfMXcaQtckJPBctTrAuSQkJ">>
     },
    oidcc:add_openid_provider(ConfigEndpoint, LocalEndpoint, Config),
    basic_client:init(),
    psycho_server:start(8080, routes_app()),
    basic_client_sup:start_link().

stop(_) ->
    ok.


routes_app() ->
    Routes =
        [{"/", fun status_page/1},
         {"/oidc", oidc_app()},
         {"/oidc/return", oidc_app()}],
    psycho_route:create_app(Routes).


status_page(Env) ->
    basic_client_http:status_page(Env).

oidc_app() ->
    oidcc_psycho:oidcc_app().
