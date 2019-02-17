%%%-------------------------------------------------------------------
%%% @author root
%%% @copyright (C) 2019, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 17. Февр. 2019 12:01
%%%-------------------------------------------------------------------
-module(mgw_pam).
-author("kreastone").

%% API
-export([login/3, logout/1, check_user/1, check_cmd/3, start_link/0]).

-define(AVAILABLE_RESOURCES, [
  {<<"sysinfo">>,     [<<"GET">>]},
  {<<"interface">>,   [<<"GET">>, <<"POST">>, <<"PATCH">>, <<"DELETE">>]},
  {<<"route">>,       [<<"GET">>]}
]).

start_link() ->
  pam_genserver:start_link().

%----------
-spec(login(
    Login :: binary(),
    Password :: binary()) ->
  {ok, ID :: integer(), Group :: integer()} | {error, Reason :: term()}).
login(Login, Password, Host) ->
  login(Login, Password, http, Host, 60, null).
-spec(login(
    Login :: binary(),
    Password :: binary(),
    Host :: binary(),
    Type :: http | ssh,
    TTL :: integer(),
    Socket :: term()) ->
  {ok, ID :: integer(), Group :: integer()} | {error, Reason :: term()}).
login(Login, Password, Type, Host, TTL, Socket) ->
  gen_server:call(pam_genserver, {login, Login, Password, Type, Host, TTL, Socket}).

%----------

-spec(logout(
    Id :: integer()) ->
  ok | {error, Reason :: term()}).
logout(Id) ->
  gen_server:call(pam_genserver, {logout, Id}).

%----------

-spec(check_user(ID) -> Result when
  ID :: non_neg_integer(),
  Result :: boolean()).
check_user(0) -> true;
check_user(ID) ->
  case mnesia:transaction(fun mnesia:read/1, [{dn_users, ID}]) of
    {atomic, []} -> false;
    {atomic, _L} -> true
  end.

%----------

-spec(check_cmd(ID, Module, Action) -> Result when
  ID :: non_neg_integer(),
  Module :: binary(),
  Action :: binary(),
  Result :: ok | {error, Reason},
  Reason :: string()).
check_cmd(ID, Module, Action) ->
  F = fun
        ({M, A}) when M == Module -> lists:any(fun(Elem) -> Elem == Action end, A);
        (_) -> false
      end,
  Status = lists:any(F, ?AVAILABLE_RESOURCES),
  error_logger:info_report([
    {apply, Status},
    {user, ID},
    {module, <<"pam_", Module/binary>>},
    {action, Action}
  ]),
  case Status of
    true -> ok;
    false -> {error, iolist_to_binary(io_lib:format("~s:~s not implemented", [Module, Action]))}
  end.