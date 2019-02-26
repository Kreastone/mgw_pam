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

-behaviour(gen_server).

%% API
-export([start_link/0]).
-export([check_ttl/0]).
-export([login/3, logout/1, check_user/1, check_cmd/3]).

-define(AVAILABLE_RESOURCES, [
  {<<"sysinfo">>,     [<<"GET">>]},
  {<<"interface">>,   [<<"GET">>, <<"POST">>, <<"PATCH">>, <<"DELETE">>]},
  {<<"route">>,       [<<"GET">>]}
]).

%% DEBUG
-export([test_start/0]).  %% TEST START
-export([show_all/0]).    %% for debug


%% gen_server callbacks
-export([init/1,
  handle_call/3,
  handle_cast/2,
  handle_info/2,
  terminate/2,
  code_change/3]).

-define(SERVER, ?MODULE).
-define(DRIVER, "pam_drv").
-define(DIR_DRIVER, "/root").

-record(state, {
  pid_pam :: pid(),
  last_id = 0 :: integer()
}).

-record(dn_users, {
  id :: mgw_util:id(),
  user :: binary(),
  group :: integer(),
  type :: mgw_util:type_connection(),
  host = <<"">> :: binary(),
  ttl = 0,
  socket :: term()
}).

%%%===================================================================

-define(LOGIN_LOCAL, 0).
-define(LOGIN_TAC_PLUS, 1).
-define(LOGIN_RADIUS, 2).
-define(LOGOUT, 3).

%%%===================================================================
%%% API
%%%===================================================================

show_all() ->
  F = fun() ->
    mnesia:foldl(fun(Rec, _Acc) -> io:format("~p~n", [Rec]), [] end, [], dn_users)
      end,
  mnesia:transaction(F).

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @end
%%--------------------------------------------------------------------

test_start() ->
  mnesia:create_schema([node()]),
  mnesia:start(),
  mnesia:create_table(dn_users, [{attributes, record_info(fields, dn_users)}]),
  mnesia:clear_table(dn_users),
  start_link().

-spec(start_link() ->
  {ok, Pid :: pid()} | ignore | {error, Reason :: term()}).
start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
-spec(init(Args :: term()) ->
  {ok, State :: #state{}} | {ok, State :: #state{}, timeout() | hibernate} |
  {stop, Reason :: term()} | ignore).
init([]) ->
  case erl_ddll:load_driver(?DIR_DRIVER, ?DRIVER) of
    ok ->
      timer:apply_interval(1000, ?MODULE, check_ttl, []),
      Pid = open_port({spawn, ?DRIVER}, []),
      {ok, #state{pid_pam = Pid}};
    {error, already_loaded} ->
      ignore;
    {error, Reason} ->
      io:format("erl_ddll error: ~p~n", [erl_ddll:format_error(Reason)]),
      ignore
  end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @end
%%--------------------------------------------------------------------
-spec(handle_call(Request :: term(), From :: {pid(), Tag :: term()},
    State :: #state{}) ->
  {reply, Reply :: term(), NewState :: #state{}} |
  {reply, Reply :: term(), NewState :: #state{}, timeout() | hibernate} |
  {noreply, NewState :: #state{}} |
  {noreply, NewState :: #state{}, timeout() | hibernate} |
  {stop, Reason :: term(), Reply :: term(), NewState :: #state{}} |
  {stop, Reason :: term(), NewState :: #state{}}).

handle_call({login, Login, Password, Type, Host, TTL, Socket}, _From, State) ->
  Pid = State#state.pid_pam,
  Id = State#state.last_id + 1,
  erlang:port_control(Pid, ?LOGIN_LOCAL, term_to_binary({Login, Password})),
  Res =
    receive
      {Pid, {data, [45|Code_Error]}} -> % example: "-1" or "-2,7". 45 is "-"
        parse_error(Code_Error);
      {Pid, {data, Group}} when is_list(Group) ->
        Int_Group = list_to_integer(Group),
        insert_row(Id, Login, Int_Group, Type, Host, TTL, Socket),
        {ok, Id, Int_Group};
      _ ->
        {error, "unknown"}
    after 7000 ->
      {error, "timeout"}
    end,
  {reply, Res, State#state{pid_pam = Pid, last_id = Id}};
handle_call({logout, Id}, _From, State) ->
  delete_row(Id),
  {reply, ok, State};
handle_call(_Request, _From, State) ->
  {reply, ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @end
%%--------------------------------------------------------------------
-spec(handle_cast(Request :: term(), State :: #state{}) ->
  {noreply, NewState :: #state{}} |
  {noreply, NewState :: #state{}, timeout() | hibernate} |
  {stop, Reason :: term(), NewState :: #state{}}).
handle_cast(_Request, State) ->
  {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
-spec(handle_info(Info :: timeout() | term(), State :: #state{}) ->
  {noreply, NewState :: #state{}} |
  {noreply, NewState :: #state{}, timeout() | hibernate} |
  {stop, Reason :: term(), NewState :: #state{}}).
handle_info(_Info, State) ->
  {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
-spec(terminate(Reason :: (normal | shutdown | {shutdown, term()} | term()),
    State :: #state{}) -> term()).
terminate(_Reason, _State) ->
  ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
-spec(code_change(OldVsn :: term() | {down, term()}, State :: #state{},
    Extra :: term()) ->
  {ok, NewState :: #state{}} | {error, Reason :: term()}).
code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

insert_row(ID, Username, Group, Type, Host, TTL, Socket) ->
  Row = #dn_users{
    id = ID,
    user = Username,
    group = Group,
    type = Type,
    host = Host,
    ttl = TTL,
    socket = Socket
  },
  mnesia:transaction(fun() -> mnesia:write(Row) end).

check_ttl() ->
  F =
    fun() ->
      List_ID = mnesia:foldl(
        fun(Rec, Acc) ->
          if (Rec#dn_users.ttl == 0) ->
            Acc ++ [Rec#dn_users.id];
            true ->
              New_Record = #dn_users{
                id = Rec#dn_users.id,
                user = Rec#dn_users.user,
                group = Rec#dn_users.group,
                type = Rec#dn_users.type,
                host = Rec#dn_users.host,
                ttl = Rec#dn_users.ttl - 1,
                socket = Rec#dn_users.socket
              },
              mnesia:write(New_Record),
              Acc
          end
        end, [], dn_users),
      delete_row(List_ID)
    end,
  mnesia:transaction(F).

delete_row([]) ->
  ok;
delete_row([ID|Table]) ->
  mnesia:delete({dn_users, ID}),
  delete_row(Table);
delete_row(ID) ->
  mnesia:transaction(fun() -> mnesia:delete({dn_users, ID}) end).

%%  -1 - Ошибка инициализации pam
%%  -2 - Ошибка аутентификации
%%  -3 - Ошибка выделения памяти malloc
%%  -4 - Ошибка получения GID
%%  -5 - Ошибка валидации учетной записи
%%  расшифровка <-2>:
%%  6 - Ошибка доступа
%%  7 - Ошибка авторизации
%%  9 - Удаленный сервер недоступен
%%  28 - отсутствует вызываемый модуль (pam_raduis.so, pam_tacacs.so)
%%  10 - ошибка получения информации о пользователе (GID) с удаленного сервера, ошибка возникает при неверных настройках сервера
parse_error(Code_Error) ->
  case (Code_Error) of
    "1" -> {error, "error init"};
    "2,6" -> {error, "error access"};
    "2,7" -> {error, "error autorization"};
    "2,9" -> {error, "error remote server is not available"};
    "2,28" -> {error, "error missing module pam_raduis.so or pam_tacacs.so"};
    "2,10" -> {error, "error get info GID"};
    "3" -> {error, "error c malloc"};
    "4" -> {error, "error get info GID"};
    "5" -> {error, "error validation"};
    _ -> {error, "unknown error"}
  end.

%----------
-spec(login(
    Login :: binary(),
    Password :: binary(),
    Host :: binary()) ->
  {ok, ID :: integer(), Group :: integer()} | {error, Reason :: term()}).
login(Login, Password, Host) ->
  login(Login, Password, http, Host, 1500, null).
-spec(login(
    Login :: binary(),
    Password :: binary(),
    Host :: binary(),
    Type :: http | ssh,
    TTL :: integer(),
    Socket :: term()) ->
  {ok, ID :: integer(), Group :: integer()} | {error, Reason :: term()}).
login(Login, Password, Type, Host, TTL, Socket) ->
  gen_server:call(?MODULE, {login, Login, Password, Type, Host, TTL, Socket}).

%----------

-spec(logout(
    Id :: integer()) ->
  ok | {error, Reason :: term()}).
logout(Id) ->
  gen_server:call(?MODULE, {logout, Id}).

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