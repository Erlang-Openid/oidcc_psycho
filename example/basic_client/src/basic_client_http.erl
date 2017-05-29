-module(basic_client_http).

-export([status_page/1,
         cookie_name/0]).

-define(COOKIE, "basic_client_session").

cookie_name() ->
    ?COOKIE.

status_page(Env) ->
    handle_status(psycho:env(cookie_value, update_env(Env))).

handle_status(undefined) ->
    Body = "
<!DOCTYPE html>
<html lang=\"en\">
    <body>
	   you are not yet logged in, please do so by following
	   <a href=\"/oidc?provider=google\">going without cookie</a>
           </br>
	   you can also login
	   <a href=\"/oidc?provider=google&use_cookie=true\">with using a cookie</a>
    </body>
</html>
",
    {{200, "OK"}, [{"Content-Type", "text/html"}, clear_cookie_header()], Body};
handle_status(_) ->
    %% Opts = [{max_age, 0},{http_only, true},{path, <<"/">>}],
    Body = "
<!DOCTYPE html>
<html lang=\"en\">
    <body>
	   you are logged in
    </body>
</html>
",
    {{200, "OK"}, [{"Content-Type", "text/html"}, clear_cookie_header()], Body}.



clear_cookie_header() ->
    Opts = [ {http_only, true}, {max_age, 0}, {path, "/"}],
    psycho_util:cookie_header(?COOKIE, "deleted", Opts).




update_env(Env0) ->
    {ParsedCookie, Env} = psycho_util:ensure_parsed_cookie(Env0),
    CookieValue = proplists:get_value(?COOKIE, ParsedCookie, undefined),
    [{cookie_value, CookieValue} | Env].
